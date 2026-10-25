"""Run with python3 -m unittest discover -s tests -v. No root or network needed."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('validator', ROOT / 'scripts/validate-site-routing.py')
assert spec is not None and spec.loader is not None
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class SiteRoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='site-routing-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.cfg = self.dir / 'wg0.conf'
        self.cfg.write_text('[Interface]\nAddress = 10.1.100.6/32\nDNS = 1.1.1.1\n[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\n')
        self.state = self.dir / 'state.json'
        self.saved = self.dir / 'saved.conf'

    def shell(self, code, check=True):
        prelude = f'''
source {shlex.quote(str(ROOT / 'scripts/setup-vpn-gateway.sh'))}
LOG_FILE=/dev/null
CONFIG_FILE={shlex.quote(str(self.saved))}
WG_CONF_SRC={shlex.quote(str(self.cfg))}
WG_CONF_PATH="$WG_CONF_SRC"
WG_CONF_DEST="$WG_CONF_SRC"
LAN_IFACE=eth1; WAN_IFACE=eth0; LAN_CIDR=10.3.0.0/24
PI_BYPASS_ROUTING=true; LAN_FORWARD_MODE=all
SITE_ROUTING_MODE=routed
SITE_REMOTE_CIDRS='192.168.20.0/24 192.168.30.0/24'
SITE_INBOUND_ACCESS=restricted; SITE_INBOUND_SOURCES=192.168.20.5/32
ip() {{ python3 {shlex.quote(str(ROOT / 'tests/mock_net.py'))} ip "$@"; }}
iptables() {{ python3 {shlex.quote(str(ROOT / 'tests/mock_net.py'))} iptables "$@"; }}
systemctl() {{ :; }}
wg-quick() {{
    local line op=PostUp
    if [ "$1" = down ]; then op=PostDown; fi
    while IFS= read -r line; do
        if [[ "$line" == "$op = "* ]]; then
            line="${{line#*= }}"; line="${{line//%i/wg0}}"; eval "$line" || return 1
        fi
    done < "$WG_CONF_DEST"
    if [ "$1" = down ]; then ip link delete wg0; else ip link add wg0; fi
}}
'''
        env = dict(os.environ, MOCK_NET_STATE=str(self.state), TERM='dumb')
        result = subprocess.run(['bash', '-c', prelude + '\n' + code], text=True, capture_output=True, env=env)
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def validate(self, **changes):
        args = dict(mode='routed', lan='10.3.0.0/24', remote='192.168.20.0/24', access='restricted',
                    sources='192.168.20.5/32', cfg=str(self.cfg), wan='192.168.10.197/24',
                    lan_iface='eth1', wan_iface='eth0', bypass='true')
        args.update(changes)
        return validator.validate(**args)

    def test_strict_validation(self):
        self.validate()
        for changes in [
            {'lan': '10.3.0.0./24'}, {'remote': '192.168.20.0./24'},
            {'remote': '192.168.20.1/24'}, {'remote': '0.0.0.0/0'},
            {'remote': '0.0.0.0/1'}, {'remote': '::/0'}, {'remote': ''},
            {'remote': '10.3.0.0/24'}, {'remote': '192.168.10.0/24'},
            {'lan': '192.168.10.0/24'},
            {'remote': '192.168.20.0/24 192.168.20.0/25'},
            {'remote': '192.168.20.0/24;touch /evil'},
            {'sources': '192.168.40.5/32'}, {'sources': ''},
            {'sources': '192.168.20.5/32$(id)'}, {'access': 'invalid'},
            {'lan_iface': 'eth1;id'}, {'bypass': 'false'}, {'mode': 'invalid'},
        ]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.validate(**changes)

    def test_actual_peer_coverage_not_interface_or_defaults_inferred(self):
        self.cfg.write_text('[Interface]\nAllowedIPs = 0.0.0.0/0\n[Peer]\nAllowedIPs = 192.168.20.0/25\n')
        with self.assertRaisesRegex(ValueError, 'actual peer AllowedIPs'):
            self.validate()
        self.cfg.write_text('[Interface]\n[Peer]\nAllowedIPs = 192.168.20.0/25, 192.168.20.128/25\n')
        self.validate()

    def test_legacy_missing_fields_remain_nat_no_routes_invented(self):
        self.saved.write_text('LAN_CIDR="10.3.0.0/24"\n')
        result = self.shell('unset SITE_ROUTING_MODE SITE_REMOTE_CIDRS SITE_INBOUND_ACCESS SITE_INBOUND_SOURCES; load_config; '
                            'echo "$SITE_ROUTING_MODE:$SITE_INBOUND_ACCESS"; _wg_iptables_up_cmds; extract_home_subnets "$WG_CONF_SRC"')
        self.assertIn('nat:outbound', result.stdout)
        self.assertNotIn('VPN_SITE', result.stdout)
        self.assertNotIn('192.168.20.', result.stdout)
        self.assertIn('-o wg0 -j MASQUERADE', result.stdout)

    def test_routed_config_contains_explicit_main_and_table_routes(self):
        self.shell('do_configure_wg_firewall_rules')
        text = self.cfg.read_text()
        self.assertIn('Table = off', text)
        self.assertNotIn('DNS =', text)
        for site in ['192.168.20.0/24', '192.168.30.0/24']:
            self.assertIn(f'ip route replace {site} dev %i\n', text)
            self.assertIn(f'ip route replace {site} dev %i table 200', text)
        self.assertIn('ip route replace default dev %i table 200', text)
        self.assertNotIn('ip route replace default dev %i\n', text)
        self.assertNotIn('ip -6 route', text)  # Explicitly IPv4-only feature.
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', text)
        self.assertIn('iif eth1 lookup 200', text)

    def test_home_mode_uses_explicit_sites_even_with_default_allowedips(self):
        self.shell('LAN_FORWARD_MODE=home; do_configure_wg_firewall_rules')
        text = self.cfg.read_text()
        self.assertNotIn('replace default', text)
        self.assertIn('192.168.20.0/24 dev %i table 200', text)

    def test_reject_before_rewriting_config(self):
        before = self.cfg.read_text()
        result = self.shell("SITE_REMOTE_CIDRS='10.3.0.0./24'; do_configure_wg_firewall_rules", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, self.cfg.read_text())

    def test_nat_ordering_access_scope_and_idempotency_with_mock_commands(self):
        self.shell('''
validate_site_routing || exit 1
# Existing persisted masquerade must stay after exemptions.
iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
commands=$(_wg_iptables_up_cmds); eval "$commands" || exit 1
eval "$commands" || exit 1
''')
        state = json.loads(self.state.read_text())
        chains = state['chains']
        self.assertEqual(chains['nat:POSTROUTING'][0], ['-j', 'VPN_SITE_NAT'])
        self.assertEqual(chains['nat:POSTROUTING'].count(['-j', 'VPN_SITE_NAT']), 1)
        self.assertIn(['-o', 'wg0', '-j', 'MASQUERADE'], chains['nat:POSTROUTING'])
        self.assertEqual(len(chains['nat:VPN_SITE_NAT']), 4)
        self.assertTrue(all(rule[-1] == 'ACCEPT' for rule in chains['nat:VPN_SITE_NAT']))
        fwd = chains['filter:VPN_SITE_FWD']
        new = [r for r in fwd if 'NEW' in r]
        self.assertEqual(len(new), 1)
        self.assertIn('192.168.20.5/32', new[0])
        self.assertIn('10.3.0.0/24', new[0])
        self.assertEqual(fwd[-1][-1], 'DROP')
        self.assertEqual(chains['filter:FORWARD'][0], ['-j', 'VPN_SITE_FWD'])

    def test_outbound_and_sites_access_choices(self):
        for access, expected in [('outbound', 0), ('sites', 2)]:
            result = self.shell(f'SITE_INBOUND_ACCESS={access}; SITE_INBOUND_SOURCES=""; validate_site_routing || exit 1; _site_iptables_up_cmds')
            self.assertEqual(result.stdout.count('--ctstate NEW'), expected)
            self.assertIn('--ctstate RELATED,ESTABLISHED', result.stdout)
            self.assertIn('-j DROP', result.stdout)

    def test_reversible_hooks_and_cleanup_leave_internet_nat_alone(self):
        self.shell('''
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
up=$(_wg_iptables_up_cmds); eval "$up"
down=$(_wg_iptables_down_cmds); eval "$down"
remove_site_routing_rules
''')
        chains = json.loads(self.state.read_text())['chains']
        self.assertFalse(any('VPN_SITE' in key for key in chains))
        self.assertEqual(chains['nat:POSTROUTING'], [['-o', 'eth0', '-j', 'MASQUERADE']])
        self.assertEqual(chains['filter:FORWARD'], [])

    def test_real_restart_path_converges_on_subnet_mode_and_interface_changes(self):
        self.shell('''
do_configure_wg_firewall_rules || exit 1
wg-quick up wg0 || exit 1
SITE_REMOTE_CIDRS=192.168.40.0/24; SITE_INBOUND_SOURCES=192.168.40.5/32
LAN_IFACE=eth2; LAN_FORWARD_MODE=home
WG_PREV_HASH=force
do_configure_wg_firewall_rules || exit 1
do_start_wireguard || exit 1
''')
        state = json.loads(self.state.read_text())
        self.assertTrue(all('192.168.20.0/24' not in r and 'default' not in r for r in state['routes']))
        self.assertIn(['4', '192.168.40.0/24', 'dev', 'wg0'], state['routes'])
        self.assertNotIn('eth1', str(state['chains']['filter:VPN_SITE_FWD']))
        self.shell('SITE_ROUTING_MODE=nat; WG_PREV_HASH=force; do_configure_wg_firewall_rules; do_start_wireguard')
        state = json.loads(self.state.read_text())
        self.assertFalse(any('VPN_SITE' in key for key in state['chains']))
        self.assertNotIn('192.168.40.0/24', str(state['routes']))

    def test_unchanged_config_does_not_restart(self):
        self.shell('''
do_configure_wg_firewall_rules || exit 1
WG_PREV_HASH=$(sha256sum "$WG_CONF_DEST" | awk '{print $1}')
do_start_wireguard
''')
        state = json.loads(self.state.read_text())
        self.assertFalse(any(c[:3] == ['ip', 'link', 'delete'] for c in state['calls']))

    def prompt(self, answers, new=False, expect_success=True, saved_mode='nat',
               saved_access='outbound', saved_sources=''):
        # Prompt functions are replaced, but real prompt flow and validation run.
        self.answers = self.dir / 'answers'
        self.answers.write_text('\n'.join(answers) + '\n')
        code = f'''
SITE_ROUTING_MODE={shlex.quote(saved_mode)}; SITE_REMOTE_CIDRS=''
SITE_INBOUND_ACCESS={shlex.quote(saved_access)}; SITE_INBOUND_SOURCES={shlex.quote(saved_sources)}
SITE_NEW_INSTALL={'true' if new else 'false'}; NONINTERACTIVE=false
exec 8< {shlex.quote(str(self.answers))}
prompt_q() {{ echo "Q:$*"; }}
prompt_h() {{ echo "H:$*"; }}
prompt_cue_default() {{ echo "C:$1 [$2]"; IFS= read -r PROMPT_REPLY <&8; }}
prompt_cue() {{ echo "C:$*"; IFS= read -r PROMPT_REPLY <&8; }}
prompt_site_routing
'''
        result = self.shell(code, check=expect_success)
        return result

    def test_new_default_and_explicit_legacy_migration_prompts(self):
        result = self.prompt(['', '192.168.20.0/24', '', 'y'], new=True)
        self.assertEqual(result.stdout.count('C:Choice [1]'), 2)
        self.assertIn('Pi-side =', result.stdout)
        self.assertIn('VPN-server-side =', result.stdout)
        self.assertIn('Selected networks above (recommended)', result.stdout)
        self.assertIn('all protocols in both directions', result.stdout)
        self.assertIn('does not open access to arbitrary Internet peers', result.stdout)
        self.assertNotIn('Q:Which VPN-server-side source networks or devices may connect?', result.stdout)
        self.assertNotIn('C:Source CIDRs', result.stdout)
        self.assertIn('Networks behind client = 10.3.0.0/24', result.stdout)
        self.assertIn('Site Magic', result.stdout)
        self.assertIn('IPv4 only', result.stdout)
        self.assertIn('SITE_ROUTING_MODE="routed"', self.saved.read_text())
        self.assertIn('SITE_INBOUND_ACCESS="sites"', self.saved.read_text())
        self.assertIn('SITE_INBOUND_SOURCES=""', self.saved.read_text())
        self.saved.unlink()
        result = self.prompt([''])
        self.assertIn('C:Choice [2]', result.stdout)
        self.assertIn('SITE_ROUTING_MODE="nat"', self.saved.read_text())
        self.prompt(['1', '192.168.20.0/24', '3', 'y'])
        self.assertIn('SITE_ROUTING_MODE="routed"', self.saved.read_text())
        self.assertIn('SITE_INBOUND_ACCESS="outbound"', self.saved.read_text())

    def test_saved_routed_access_defaults_are_preserved(self):
        for access, choice, sources in [('sites', '1', ''),
                                        ('restricted', '2', '192.168.20.5/32'),
                                        ('outbound', '3', '')]:
            with self.subTest(access=access):
                answers = ['', '192.168.20.0/24', '']
                if access == 'restricted':
                    answers.append('')
                result = self.prompt(answers + ['y'], saved_mode='routed',
                                     saved_access=access, saved_sources=sources)
                cues = [line for line in result.stdout.splitlines() if line.startswith('C:Choice')]
                self.assertEqual(cues, ['C:Choice [1]', f'C:Choice [{choice}]'])
                self.assertIn(f'SITE_INBOUND_ACCESS="{access}"', self.saved.read_text())
                self.assertIn(f'SITE_INBOUND_SOURCES="{sources}"', self.saved.read_text())

    def test_new_routed_selection_defaults_sites_and_offers_restricted(self):
        result = self.prompt(['1', '192.168.20.0/24', '', 'y'])
        self.assertIn('C:Choice [2]', result.stdout)  # Legacy mode default, not silent migration.
        self.assertIn('SITE_INBOUND_ACCESS="sites"', self.saved.read_text())
        self.prompt(['', '192.168.20.0/24', '2', '192.168.20.5/32', 'y'], new=True)
        self.assertIn('SITE_INBOUND_ACCESS="restricted"', self.saved.read_text())
        self.assertIn('SITE_INBOUND_SOURCES="192.168.20.5/32"', self.saved.read_text())

    def test_cancel_migration_and_bad_inputs_do_not_save(self):
        result = self.prompt(['1', '192.168.20.0/24', '1', 'n'], expect_success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.saved.exists())
        result = self.prompt(['1', '192.168.20.0./24', '1'], expect_success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.saved.exists())

    def test_noninteractive_legacy_and_new_missing_networks(self):
        self.shell('SITE_ROUTING_MODE=nat; SITE_NEW_INSTALL=false; NONINTERACTIVE=true; prompt_site_routing')
        self.assertIn('SITE_ROUTING_MODE="nat"', self.saved.read_text())
        self.saved.unlink()
        result = self.shell('SITE_NEW_INSTALL=true; SITE_REMOTE_CIDRS=""; NONINTERACTIVE=true; prompt_site_routing', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.saved.exists())

    def test_apply_start_cleanup_and_edit_wiring(self):
        setup = (ROOT / 'scripts/setup-vpn-gateway.sh').read_text()
        manage = (ROOT / 'gateway-manage-or-setup.sh').read_text()
        edit = (ROOT / 'scripts/selective-edit.sh').read_text()
        cleanup = (ROOT / 'scripts/cleanup-gateway.sh').read_text()
        self.assertIn('NONINTERACTIVE=true bash "$SETUP_SCRIPT"', manage)
        self.assertIn('--prepare-start', manage)
        self.assertIn('prepare_saved_start', setup)
        self.assertIn('do_configure_lan_ready_service || return 1', setup)
        self.assertIn('13) key="site_routing"', edit)
        self.assertIn('wg_conf|pi_bypass|lan_forward|site_routing)', edit)
        self.assertIn('remove_site_routing_rules', cleanup)

    def test_prepare_saved_start_executes_legacy_and_routed_without_prompts(self):
        installed = self.dir / 'installed.conf'
        for routed in (False, True):
            self.saved.write_text(
                f'WAN_IFACE=eth0\nLAN_IFACE=eth1\nLAN_CIDR=10.3.0.0/24\nWG_CONF_PATH={shlex.quote(str(self.cfg))}\n'
                'PI_BYPASS_ROUTING=true\nLAN_FORWARD_MODE=all\n' +
                ('SITE_ROUTING_MODE=routed\nSITE_REMOTE_CIDRS=192.168.20.0/24\nSITE_INBOUND_ACCESS=outbound\n' if routed else ''))
            result = self.shell(f'''
unset SITE_ROUTING_MODE SITE_REMOTE_CIDRS SITE_INBOUND_ACCESS SITE_INBOUND_SOURCES
init_log() {{ :; }}
check_root() {{ :; }}
_edit_refresh_lan_gateway() {{ LAN_GATEWAY=10.3.0.1; WG_CONF_DEST={shlex.quote(str(installed))}; }}
do_configure_lan_ready_service() {{ echo repaired-lan-unit; }}
do_software_watchdog_setup() {{ echo repaired-dropins; }}
persist_iptables_rules() {{ echo persisted; }}
prompt_q() {{ echo 'UNEXPECTED PROMPT' >&2; exit 99; }}
prepare_saved_start
''')
            text = installed.read_text()
            self.assertEqual('PostUp = iptables -t nat -N VPN_SITE_NAT' in text, routed)
            self.assertIn('repaired-lan-unit', result.stdout)
            self.assertIn('repaired-dropins', result.stdout)
            self.assertIn('persisted', result.stdout)

    def test_routed_bypass_cannot_be_disabled_by_single_setting(self):
        result = self.shell('_edit_prompt_setting pi_bypass', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.saved.exists())

    def test_prompt_layout_question_helper_cue_order(self):
        result = self.prompt(['1', '192.168.20.0/24', '3', 'y'])
        lines = [line for line in result.stdout.splitlines() if line[:2] in ('Q:', 'H:', 'C:')]
        self.assertEqual(lines[0][:2], 'Q:')
        for index, line in enumerate(lines):
            if line.startswith('C:'):
                self.assertTrue(lines[index - 1].startswith('H:'))
            if line.startswith('Q:') and index:
                self.assertTrue(lines[index - 1].startswith('C:'))


if __name__ == '__main__':
    unittest.main()
