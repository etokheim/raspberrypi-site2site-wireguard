"""Whole-script audit regressions; source helpers only, all network effects mocked."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ScriptAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='gateway-audit-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.saved = self.dir / 'saved.conf'
        self.cfg = self.dir / 'wg0.conf'
        self.cfg.write_text('[Interface]\nPrivateKey = TEST_SECRET\n[Peer]\nAllowedIPs = 192.168.20.0/24\n')
        self.cfg.chmod(0o600)

    def shell(self, code, **values):
        prelude = f'source {shlex.quote(str(ROOT / "scripts/setup-vpn-gateway.sh"))}\n'
        defaults = dict(LOG_FILE=str(self.dir / 'test.log'), CONFIG_FILE=str(self.saved),
                        WG_CONF_SRC=str(self.cfg), WG_CONF_DEST=str(self.cfg),
                        WG_CONF_PATH=str(self.cfg), SITE_ROUTING_MODE='nat', LAN_IFACE='eth1',
                        WAN_IFACE='eth0', LAN_CIDR='10.3.0.0/24', PI_BYPASS_ROUTING='true',
                        LAN_FORWARD_MODE='all', NONINTERACTIVE='true')
        defaults.update(values)
        prelude += '\n'.join(f'{k}={shlex.quote(v)}' for k, v in defaults.items()) + '\n'
        # No test may accidentally fall through to host network/service commands.
        prelude += '''
ip() { echo "unexpected ip call" >&2; return 99; }
iptables() { echo "unexpected iptables call" >&2; return 99; }
systemctl() { echo "unexpected systemctl call" >&2; return 99; }
wg-quick() { echo "unexpected wg-quick call" >&2; return 99; }
progress_draw_box() { :; }
ui_printf() { :; }
ui_echo() { :; }
'''
        return subprocess.run(['bash', '-c', prelude + code], cwd=self.dir,
                              env=dict(os.environ, TERM='dumb'), text=True, capture_output=True)

    def test_saved_values_are_literal_data_on_load_and_update(self):
        values = ['$(touch INJECTED)', '`touch INJECTED`', '"; touch INJECTED; #',
                  'back\\slash $HOME "quoted"', 'line one\nline two', 'ordinary ssid']
        for value in values:
            with self.subTest(value=value):
                self.saved.unlink(missing_ok=True)
                (self.dir / 'INJECTED').unlink(missing_ok=True)
                result = self.shell('''
save_config_var AP_SSID "$VALUE" || exit 1
unset AP_SSID
source "$CONFIG_FILE"
[ "$AP_SSID" = "$VALUE" ] || exit 2
save_config_var AP_SSID replacement || exit 3
source "$CONFIG_FILE"
[ "$AP_SSID" = replacement ]
''', VALUE=value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.dir / 'INJECTED').exists())
                self.assertEqual(self.saved.stat().st_mode & 0o777, 0o600)

    def test_config_temp_does_not_follow_predictable_symlink(self):
        victim = self.dir / 'victim'
        victim.write_text('keep me')
        self.saved.write_text('AP_PASS="old secret"\n')
        Path(str(self.saved) + '.tmp').symlink_to(victim)
        result = self.shell('umask 022; save_config_var AP_PASS "new secret"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(victim.read_text(), 'keep me')

    def edit(self, src, dest):
        return self.shell('''
_edit_refresh_lan_gateway() { :; }
validate_site_routing() { :; }
prompt_q() { :; }; prompt_h() { :; }; prompt_cue() { PROMPT_REPLY=y; }
become_unattended() { :; }
do_configure_wg_firewall_rules() { :; }
do_start_wireguard() { :; }
ensure_nat_rules() { :; }; persist_iptables_rules() { :; }
do_verify_routes() { :; }
_edit_apply_setting wg_conf
''', WG_CONF_SRC=str(src), WG_CONF_PATH=str(src), WG_CONF_DEST=str(dest))

    def test_peer_path_is_not_evaluated_as_shell_code(self):
        src = self.dir / 'peer$(touch INJECTED).conf'
        src.write_text(self.cfg.read_text())
        result = self.edit(src, self.cfg)
        self.assertFalse((self.dir / 'INJECTED').exists(), result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(src.read_text(), self.cfg.read_text())

    def test_install_allows_source_equal_destination(self):
        result = self.edit(self.cfg, self.cfg)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('same file', (self.dir / 'test.log').read_text())
        self.assertIn('TEST_SECRET', self.cfg.read_text())

    def test_rewrite_keeps_key_private_and_ignores_predictable_temp(self):
        victim = self.dir / 'victim'
        victim.write_text('keep me')
        Path(str(self.cfg) + '.tmp').symlink_to(victim)
        result = self.shell('umask 022; do_configure_wg_firewall_rules')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(victim.read_text(), 'keep me')
        self.assertEqual(self.cfg.stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.cfg.is_symlink())

    def test_rewrite_normalizes_valid_wg_whitespace_and_crlf(self):
        self.cfg.write_bytes(b'  [Interface]\r\nPrivateKey = TEST_SECRET\r\nTable=auto\r\n DNS=9.9.9.9\r\nPostUp=echo old\r\nPostDown = echo old\r\n[Peer]\r\nAllowedIPs = 192.168.20.0/24\r\n')
        result = self.shell('do_configure_wg_firewall_rules')
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.cfg.read_text()
        self.assertIn('Table = off', text)
        self.assertNotIn('Table=auto', text)
        self.assertNotIn('echo old', text)
        self.assertNotIn('DNS=', text)

    def test_rewrite_mode_is_private_without_preexisting_temp(self):
        result = self.shell('umask 022; do_configure_wg_firewall_rules')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cfg.stat().st_mode & 0o777, 0o600)

    def test_rewrite_write_failure_preserves_original(self):
        before = self.cfg.read_bytes()
        result = self.shell('''
printf() {
    if [ "${2:-}" = 'PrivateKey = TEST_SECRET' ]; then return 73; fi
    builtin printf "$@"
}
do_configure_wg_firewall_rules
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cfg.read_bytes(), before)
        self.assertEqual(list(self.dir.glob('wg0.conf.tmp.*')), [])

    def test_invalid_header_does_not_partially_strip_config(self):
        self.cfg.write_text('# [Interface] is missing\nPostUp = keep\n[Peer]\n')
        before = self.cfg.read_bytes()
        result = self.shell('do_configure_wg_firewall_rules')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cfg.read_bytes(), before)

    def test_failed_required_step_does_not_continue_to_success(self):
        for registered in (False, True):
            with self.subTest(registered=registered):
                result = self.shell(('progress_add_step critical\n' if registered else '') +
                                    'progress_run_step critical "false"\necho WRONG_SUCCESS\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('WRONG_SUCCESS', result.stdout)

    def test_tagged_firewall_removal_uses_rule_numbers_not_shell_quotes(self):
        result = self.shell('''
FW_RULE_TAG=vpn-gateway
iptables-save() { printf '%s\n' '-A INPUT -i eth0 -m comment --comment "vpn-gateway" -j DROP'; }
iptables() {
    if [ "$1" = -S ]; then
        printf '%s\n' '-P INPUT ACCEPT' \
            '-A INPUT -m comment --comment unrelated -j ACCEPT' \
            '-A INPUT -i eth0 -m comment --comment "vpn-gateway" -j DROP' \
            '-A INPUT -i eth1 -m comment --comment vpn-gateway -j ACCEPT'
    else
        printf '<%s>' "$@"; printf '\n'
    fi
}
remove_tagged_input_rules
cat "$LOG_FILE"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['<-D><INPUT><3>', '<-D><INPUT><2>'])

    def remove_input_listing(self, listing, tag='vpn-gateway', prelude=''):
        return self.shell(prelude + '''
iptables() {
    if [ "$1" = -S ]; then
        printf '%s\n' "$LISTING"
    else
        printf '<%s>' "$@" >> "$DELETIONS"
        printf '\n' >> "$DELETIONS"
    fi
}
remove_gateway_input_rules "$TAG"
''', LISTING=listing, TAG=tag, DELETIONS=str(self.dir / 'deletions'))

    def test_embedded_ownership_comment_is_not_owned(self):
        # Exact independent-review counterexample, followed by a genuine owner.
        unrelated = '-A INPUT -s 203.0.113.5 -m comment --comment "operator note --comment vpn-gateway retained" -j ACCEPT'
        result = self.remove_input_listing(unrelated + '\n' +
                                          '-A INPUT -m comment --comment vpn-gateway -j DROP')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.dir / 'deletions').read_text(), '<-D><INPUT><2>\n')

    def test_ownership_compares_complete_decoded_comment_argument(self):
        cases = [
            ('vpn-gateway', 'vpn-gateway'),
            ('vpn-gateway', '"vpn-gateway"'),
            ('vpn-gateway', "'vpn-gateway'"),
            ('vpn-gateway', r'vpn\-gateway'),
            ('Site_2.prod:WAN-01', '"Site_2.prod:WAN-01"'),
            ('a', 'a'),
            ('a' * 64, 'a' * 64),
        ]
        for tag, encoded in cases:
            with self.subTest(tag=tag, encoded=encoded):
                (self.dir / 'deletions').unlink(missing_ok=True)
                result = self.remove_input_listing(
                    '-P INPUT ACCEPT\n-A INPUT -m comment --comment "prefix ' +
                    tag.replace('\\', '\\\\').replace('"', '\\"') + ' suffix" -j ACCEPT\n' +
                    f'-A INPUT -m comment --comment {encoded} -j DROP', tag)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.dir / 'deletions').read_text(), '<-D><INPUT><2>\n')

    def test_libxtables_apostrophe_tag_counterexamples_fail_closed(self):
        # Actual libxtables output for comment vpn'gateway. shlex decodes this
        # to a DIFFERENT identity: vpn\'gateway, so neither identity is allowed.
        listing = r'''-A INPUT -m comment --comment "vpn\'gateway" -j ACCEPT'''
        for tag in ("vpn'gateway", r"vpn\'gateway"):
            with self.subTest(tag=tag):
                result = self.remove_input_listing(listing, tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Unsupported firewall ownership tag', result.stderr)
                self.assertFalse((self.dir / 'deletions').exists())

    def test_unsupported_tags_refused_before_any_iptables_call(self):
        invalid = ["vpn'gateway", r"vpn\'gateway", '', 'vpn gateway',
                   r'vpn\gateway', 'vpn"gateway', 'vpn#gateway', '-vpn',
                   'a' * 65, 'vpn\ngateway', 'vépñ', '$(touch INJECTED)']
        calls = self.dir / 'calls'
        for cleanup, entry in ((False, 'remove_gateway_input_rules "$FW_RULE_TAG"'),
                               (False, 'remove_tagged_input_rules'),
                               (False, 'ensure_wan_firewall_rules'),
                               (True, 'cleanup_wan_firewall_rules')):
            for tag in invalid:
                with self.subTest(cleanup=cleanup, entry=entry, tag=tag):
                    calls.unlink(missing_ok=True)
                    prelude = (f'source {shlex.quote(str(ROOT / "scripts/cleanup-gateway.sh"))}\n'
                               if cleanup else '')
                    result = self.shell(prelude + '''
iptables() { printf '%s\n' "$*" >> "$CALLS"; }
persist_iptables_rules() { echo persist >> "$CALLS"; }
''' + entry, FW_RULE_TAG=tag, CALLS=str(calls))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Unsupported firewall ownership tag', result.stderr)
                    self.assertFalse(calls.exists())
                    self.assertFalse((self.dir / 'INJECTED').exists())

    def test_public_entrypoints_reject_tags_before_execution_phase(self):
        calls = self.dir / 'calls'
        for cleanup, entry in ((False, 'main'), (False, 'prepare_saved_start'),
                               (False, 'run_selective_edit'),
                               (False, '_edit_apply_setting wan_iface'),
                               (False, '_edit_apply_setting firewall'),
                               (True, 'main')):
            for tag in ("vpn'gateway", r"vpn\'gateway", ''):
                with self.subTest(cleanup=cleanup, entry=entry, tag=tag):
                    calls.unlink(missing_ok=True)
                    self.saved.write_text('FW_RULE_TAG=' + shlex.quote(tag) + '\n')
                    prelude = (f'source {shlex.quote(str(ROOT / "scripts/cleanup-gateway.sh"))}\n'
                               if cleanup else '')
                    # Keep all paths local even after sourcing standalone cleanup.
                    prelude += f'CONFIG_FILE={shlex.quote(str(self.saved))}\n'
                    result = self.shell(prelude + '''
init_log() { :; }; check_root() { :; }
iptables() { echo iptables >> "$CALLS"; }
ip() { echo ip >> "$CALLS"; }
systemctl() { echo systemctl >> "$CALLS"; }
wg-quick() { echo wg-quick >> "$CALLS"; }
_edit_refresh_lan_gateway() { echo refresh >> "$CALLS"; }
print_header() { echo header >> "$CALLS"; }
''' + entry, FW_RULE_TAG=tag, CALLS=str(calls))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Unsupported firewall ownership tag', result.stderr)
                    self.assertFalse(calls.exists())

    def test_safe_custom_tag_install_and_cleanup_preserve_default_owner(self):
        state = self.dir / 'net.json'
        tag = 'Site_2.prod:WAN-01'
        result = self.shell(self.net_prelude() + '''
persist_iptables_rules() { :; }
iptables -A INPUT -m comment --comment vpn-gateway -j ACCEPT
ensure_wan_firewall_rules || exit 1
ensure_wan_firewall_rules || exit 2
''', FW_RULE_TAG=tag, MOCK_NET_STATE=str(state))
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = json.loads(state.read_text())['chains']['filter:INPUT']
        self.assertEqual(sum(r[-1] == 'DROP' for r in rules), 1)
        self.assertEqual(sum(tag in r for r in rules), 6)
        result = self.shell(self.net_prelude() + f'''
source {shlex.quote(str(ROOT / 'scripts/cleanup-gateway.sh'))}
LOG_FILE={shlex.quote(str(self.dir / 'cleanup.log'))}
cleanup_wan_firewall_rules
''', FW_RULE_TAG=tag, MOCK_NET_STATE=str(state))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(state.read_text())['chains']['filter:INPUT'],
                         [['-m', 'comment', '--comment', 'vpn-gateway', '-j', 'ACCEPT']])

    def test_escaped_embedded_comment_and_shell_text_remain_data(self):
        listing = '\n'.join([
            r'-A INPUT -m comment --comment "operator \" --comment vpn-gateway retained" -j ACCEPT',
            r'-A INPUT -m comment --comment "operator \\ --comment vpn-gateway retained" -j ACCEPT',
            r'-A INPUT -m comment --comment "$(touch INJECTED) `touch INJECTED` --comment vpn-gateway retained" -j ACCEPT',
            '-A INPUT -m comment --comment vpn-gateway-suffix -j ACCEPT',
            '-A INPUT -m comment --comment "" -j ACCEPT',
        ])
        result = self.remove_input_listing(listing)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.dir / 'deletions').exists())
        self.assertFalse((self.dir / 'INJECTED').exists())

    def test_malformed_firewall_listing_fails_before_any_deletion(self):
        malformed = [
            '-A INPUT -m comment --comment "unterminated',
            "-A INPUT -m comment --comment 'unterminated",
            '-A INPUT -m comment --comment trailing' + '\\',
            '-A INPUT -m comment --comment',
            '-A INPUT -m comment --comment vpn-gateway --comment other -j ACCEPT',
            '-A FORWARD -m comment --comment vpn-gateway -j ACCEPT',
        ]
        for line in malformed:
            with self.subTest(line=line):
                (self.dir / 'deletions').unlink(missing_ok=True)
                result = self.remove_input_listing(
                    '-A INPUT -m comment --comment vpn-gateway -j DROP\n' + line)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Refusing firewall deletion:', result.stderr)
                self.assertFalse((self.dir / 'deletions').exists())

    def test_firewall_parser_missing_python_fails_closed_in_setup_and_cleanup(self):
        for cleanup in (False, True):
            with self.subTest(cleanup=cleanup):
                prelude = (f'source {shlex.quote(str(ROOT / "scripts/cleanup-gateway.sh"))}\n'
                           if cleanup else '')
                prelude += '''
command() { if [ "$*" = '-v python3' ]; then return 1; fi; builtin command "$@"; }
'''
                result = self.remove_input_listing(
                    '-A INPUT -m comment --comment vpn-gateway -j DROP', prelude=prelude)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Firewall ownership parsing needs python3', result.stderr)
                self.assertFalse((self.dir / 'deletions').exists())

    def test_firewall_accept_failure_does_not_install_drop(self):
        result = self.shell('''
FW_RULE_TAG=vpn-gateway
remove_tagged_input_rules() { :; }
persist_iptables_rules() { :; }
iptables() { printf '%s\n' "$*" >> "$CALLS"; return 1; }
ensure_wan_firewall_rules
''', CALLS=str(self.dir / 'calls'))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('-j DROP', (self.dir / 'calls').read_text())

    def test_firewall_tag_has_a_nonempty_default(self):
        result = self.shell('''
unset FW_RULE_TAG
remove_gateway_input_rules() { printf 'remove:<%s>\n' "$1"; }
iptables() { printf '<%s>' "$@"; printf '\n'; }
persist_iptables_rules() { :; }
ensure_wan_firewall_rules
cat "$LOG_FILE"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('remove:<vpn-gateway>', result.stdout)
        self.assertIn('<--comment><vpn-gateway>', result.stdout)

    def test_persistence_failure_is_reported(self):
        result = self.shell('netfilter-persistent() { return 42; }; persist_iptables_rules')
        self.assertEqual(result.returncode, 42)

    def test_previous_lan_that_is_now_wan_is_not_flushed(self):
        result = self.shell('''
detect_ssh_iface() { echo eth0; }
nmcli() { echo "NM:$*" >> "$CALLS"; }
systemctl() { return 0; }
ip() { echo "IP:$*" >> "$CALLS"; return 1; }
iptables() { return 1; }
reset_previous_lan_iface eth0 eth1 false
''', CALLS=str(self.dir / 'calls'))
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.dir / 'calls').read_text()
        self.assertNotIn('addr flush dev eth0', calls)
        self.assertNotIn('con down', calls)

    def test_full_tunnel_guard_survives_wg_down_and_home_transition(self):
        state = self.dir / 'net.json'
        code = f'''
export MOCK_NET_STATE
iptables() {{ python3 {shlex.quote(str(ROOT / 'tests/mock_net.py'))} iptables "$@"; }}
ip() {{ python3 {shlex.quote(str(ROOT / 'tests/mock_net.py'))} ip "$@"; }}
ensure_nat_rules || exit 1
up=$(_wg_iptables_up_cmds); eval "$up" || exit 2
down=$(_wg_iptables_down_cmds); eval "$down" || exit 3
ip link delete wg0
'''
        # The mock only serializes scratch state; these commands never reach OS networking.
        result = self.shell(code, MOCK_NET_STATE=str(state))
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(state.read_text())
        self.assertEqual(data['chains']['filter:FORWARD'][0], ['-j', 'VPN_GW_EGRESS'])
        self.assertIn(['-i', 'eth1', '!', '-o', 'wg0', '-j', 'REJECT'],
                      data['chains']['filter:VPN_GW_EGRESS'])
        result = self.shell(code.split('ensure_nat_rules')[0] + 'LAN_FORWARD_MODE=home; ensure_nat_rules',
                            MOCK_NET_STATE=str(state))
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(state.read_text())
        self.assertEqual(data['chains']['filter:VPN_GW_EGRESS'], [])
        self.assertIn(['-i', 'eth1', '-o', 'eth0', '-j', 'ACCEPT'], data['chains']['filter:FORWARD'])

    def net_prelude(self):
        return f'''
export MOCK_NET_STATE
iptables() {{ python3 {shlex.quote(str(ROOT / 'tests/mock_net.py'))} iptables "$@"; }}
ip() {{ python3 {shlex.quote(str(ROOT / 'tests/mock_net.py'))} ip "$@"; }}
'''

    def test_firewall_reapply_then_cleanup_keeps_unrelated_rules(self):
        state = self.dir / 'net.json'
        result = self.shell(self.net_prelude() + '''
unset FW_RULE_TAG
persist_iptables_rules() { :; }
iptables -A INPUT -i eth0 -m comment --comment vpn-gateway -j DROP
iptables -A INPUT -s 203.0.113.5 -j ACCEPT
iptables -A INPUT -s 203.0.113.5 -m comment --comment "operator note --comment vpn-gateway retained" -j ACCEPT
ensure_wan_firewall_rules || exit 1
ensure_wan_firewall_rules || exit 2
''', MOCK_NET_STATE=str(state))
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = json.loads(state.read_text())['chains']['filter:INPUT']
        drops = [r for r in rules if r[-1] == 'DROP']
        self.assertEqual(len(drops), 1)
        ssh = next(r for r in rules if '--dport' in r)
        self.assertLess(rules.index(ssh), rules.index(drops[0]))
        result = self.shell(self.net_prelude() + f'''
source {shlex.quote(str(ROOT / 'scripts/cleanup-gateway.sh'))}
LOG_FILE={shlex.quote(str(self.dir / 'cleanup.log'))}
cleanup_wan_firewall_rules
''', MOCK_NET_STATE=str(state))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(state.read_text())['chains']['filter:INPUT'],
                         [['-s', '203.0.113.5', '-j', 'ACCEPT'],
                          ['-s', '203.0.113.5', '-m', 'comment', '--comment',
                           'operator note --comment vpn-gateway retained', '-j', 'ACCEPT']])

    def test_guard_rerun_interface_change_and_cleanup(self):
        state = self.dir / 'net.json'
        result = self.shell(self.net_prelude() + '''
ensure_nat_rules || exit 1
ensure_nat_rules || exit 2
LAN_IFACE=eth2
ensure_nat_rules || exit 3
''', MOCK_NET_STATE=str(state))
        self.assertEqual(result.returncode, 0, result.stderr)
        chains = json.loads(state.read_text())['chains']
        self.assertEqual(chains['filter:FORWARD'].count(['-j', 'VPN_GW_EGRESS']), 1)
        self.assertEqual(chains['filter:VPN_GW_EGRESS'],
                         [['-i', 'eth2', '!', '-o', 'wg0', '-j', 'REJECT']])
        result = self.shell(self.net_prelude() + f'''
source {shlex.quote(str(ROOT / 'scripts/cleanup-gateway.sh'))}
LOG_FILE={shlex.quote(str(self.dir / 'cleanup.log'))}
cleanup_gateway_nat_rules
''', MOCK_NET_STATE=str(state), LAN_IFACE='eth2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('VPN_GW_EGRESS', state.read_text().split('"calls":')[0])


if __name__ == '__main__':
    unittest.main()
