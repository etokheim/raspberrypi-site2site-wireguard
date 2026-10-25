#!/usr/bin/env python3
"""Small stateful command-generation test double; never touches networking."""
import json
import os
import sys
from pathlib import Path

path = Path(os.environ['MOCK_NET_STATE'])
state = json.loads(path.read_text()) if path.exists() else {'chains': {}, 'routes': [], 'rules': [], 'link': True, 'calls': []}
command, *args = sys.argv[1:]
state['calls'].append([command] + args)
status = 0
output = ''
if command == 'iptables':
    table = 'filter'
    if args[:1] == ['-t']:
        table, args = args[1], args[2:]
    action, chain, *rule = args
    key = table + ':' + chain
    chains = state['chains']
    if action == '-N':
        if key in chains:
            status = 1
        else:
            chains[key] = []
    elif action == '-X':
        if key not in chains:
            status = 1
        else:
            del chains[key]
    else:
        rules = chains.setdefault(key, [])
        if action == '-F':
            rules.clear()
        elif action == '-C':
            status = 0 if rule in rules else 1
        elif action == '-D':
            if rule in rules:
                rules.remove(rule)
            else:
                status = 1
        elif action == '-A':
            rules.append(rule)
        elif action == '-I':
            rules.insert(int(rule[0]) - 1, rule[1:])
        else:
            raise ValueError(args)
elif command == 'ip':
    family = '4'
    if args[:1] == ['-6']:
        family, args = '6', args[1:]
    if args[:4] == ['-o', '-4', 'addr', 'show']:
        output = '2: eth0 inet 192.168.10.197/24 scope global eth0\n'
    elif args[:2] == ['link', 'show']:
        status = 0 if state['link'] else 1
    elif args[:2] == ['link', 'delete']:
        state['link'] = False
        state['routes'] = [r for r in state['routes'] if 'wg0' not in r]
    elif args[:2] == ['link', 'add']:
        state['link'] = True
    elif args[:2] == ['route', 'replace']:
        route = [family] + args[2:]
        if route not in state['routes']:
            state['routes'].append(route)
    elif args[:2] == ['route', 'del']:
        route = [family] + args[2:]
        if route in state['routes']:
            state['routes'].remove(route)
        else:
            status = 1
    elif args[:2] == ['route', 'flush']:
        table = args[-1]
        state['routes'] = [r for r in state['routes'] if not (r[0] == family and r[-2:] == ['table', table])]
    elif args[:2] == ['rule', 'list']:
        output = '\n'.join(' '.join(r[1:]) for r in state['rules'] if r[0] == family)
    elif args[:2] in (['rule', 'add'], ['rule', 'del']):
        rule = [family] + args[2:]
        if args[1] == 'add':
            state['rules'].append(rule)
        elif rule in state['rules']:
            state['rules'].remove(rule)
        else:
            status = 1
    else:
        raise ValueError(args)
else:
    raise ValueError(command)
path.write_text(json.dumps(state))
sys.stdout.write(output)
sys.exit(status)
