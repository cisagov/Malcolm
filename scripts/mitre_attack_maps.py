#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Generate the MITRE ATT&CK lookup dictionaries in logstash/maps from MITRE's ATT&CK STIX data
#   (https://github.com/mitre-attack/attack-stix-data).
#
# For each framework (enterprise, ics, and optionally mobile), this writes:
#
#   mitre_attack_tactic_<framework>_ids.yaml          tactic name -> tactic ID(s)
#   mitre_attack_tactic_<framework>_names.yaml        tactic ID -> tactic name
#   mitre_attack_tactic_<framework>_reference.yaml    tactic name -> reference URL(s)
#   mitre_attack_technique_<framework>_ids.yaml       technique name -> technique ID(s)
#   mitre_attack_technique_<framework>_names.yaml     technique/subtechnique ID -> name
#   mitre_attack_technique_<framework>_reference.yaml technique name -> reference URL(s)
#   mitre_attack_asset_<framework>_ids.yaml           asset name -> asset ID(s) (if the framework has assets)
#   mitre_attack_asset_<framework>_names.yaml         asset ID -> asset name (if the framework has assets)
#
# Names in the *_names.yaml files are ATT&CK's own (e.g., "Exploit Public-Facing Application"). Keys in the
#   *_ids.yaml and *_reference.yaml files are names with every run of non-alphanumeric characters replaced
#   by an underscore (e.g., "Exploit_Public_Facing_Application"), the form the Logstash pipelines look
#   names up with.
#
# Names that other tools use but ATT&CK doesn't (e.g., Defense_Evasion for the renamed TA0005, or the
#   bzar notice sub-categories) are defined in ALIASES below and merged into the *_ids.yaml and
#   *_reference.yaml files. Edit ALIASES, not the generated files.
#
# The generated files are committed to the repository and copied into the Logstash image; this script is
#   only run by developers when updating to a new ATT&CK release. Review the resulting diff before
#   committing.

import argparse
import json
import logging
import os
import re
import sys
import urllib.request

import yaml

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))

STIX_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{framework}-attack/{framework}-attack{version}.json'
FRAMEWORKS_DEFAULT = ('enterprise', 'ics')
FRAMEWORKS_ALL = ('enterprise', 'ics', 'mobile')
OUTPUT_DIR_DEFAULT = os.path.realpath(os.path.join(script_path, '..', 'logstash', 'maps'))

# Names that other tools use for ATT&CK tactics and techniques but ATT&CK itself doesn't, mapped to
#   ATT&CK IDs, by framework and kind. Keys use the same form as the generated name-keyed files
#   (non-alphanumeric runs as underscores); a key can map to one ID or a list of IDs.
ALIASES = {
    'enterprise': {
        'tactic': {
            # TA0005's name before ATT&CK v18 split it into Stealth (TA0005) and Defense Impairment
            #   (TA0112), still used by older STIX bundles and by mitre-attack/bzar notices
            'Defense_Evasion': 'TA0005',
            # mitre-attack/bzar notice sub-categories
            'Lateral_Movement_and_Execution': ['TA0002', 'TA0008'],
            'Lateral_Movement_Extracted_File': 'TA0008',
            'Lateral_Movement_Multiple_Attempts': 'TA0008',
        },
    },
    'ics': {
        'tactic': {
            # short forms of the ICS tactic names used by cisagov/acid notices
            'Impair_Process': 'TA0106',
            'Inhibit_Response': 'TA0107',
        },
    },
}

STIX_TYPES = {
    'x-mitre-tactic': 'tactic',
    'attack-pattern': 'technique',
    'x-mitre-asset': 'asset',
}
REFERENCE_PATHS = {
    'tactic': 'tactics',
    'technique': 'techniques',
}


###################################################################################################
def lookup_key(name):
    """The key form used for name-based lookups: non-alphanumeric runs as underscores"""
    return re.sub(r'[^A-Za-z0-9]+', '_', name).strip('_')


def reference_url(kind, attack_id):
    """attack.mitre.org reference URL for an ID (subtechniques as /T1059/001/)"""
    return f"https://attack.mitre.org/{REFERENCE_PATHS[kind]}/{'/'.join(attack_id.split('.', 1))}/"


def id_sort_key(attack_id):
    """Sort IDs by prefix and number (T1001 < T1001.001 < T1002)"""
    match = re.match(r'^([A-Z]+)(\d+)(?:\.(\d+))?$', attack_id)
    if not match:
        return (attack_id, 0, -1)
    return (match.group(1), int(match.group(2)), int(match.group(3)) if match.group(3) else -1)


###################################################################################################
def load_bundle(framework, version, input_dir):
    """Load a framework's STIX bundle from input_dir if given, otherwise download it"""
    if input_dir:
        file_name = f"{framework}-attack{'-' + version if version else ''}.json"
        path = os.path.join(input_dir, file_name)
        logging.info(f'Reading {path}')
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    url = STIX_URL.format(framework=framework, version=f'-{version}' if version else '')
    logging.info(f'Downloading {url}')
    with urllib.request.urlopen(url, timeout=300) as response:
        return json.loads(response.read().decode('utf-8'))


def parse_bundle(bundle):
    """Return the bundle's ATT&CK version and {kind: {id: (name, deprecated)}} for current (non-revoked) objects"""
    version = None
    objects = {kind: {} for kind in STIX_TYPES.values()}
    for obj in bundle.get('objects', []):
        if obj.get('type') == 'x-mitre-collection':
            version = obj.get('x_mitre_version', version)
            continue
        kind = STIX_TYPES.get(obj.get('type'))
        if (kind is None) or obj.get('revoked'):
            continue
        attack_ids = [
            ref['external_id']
            for ref in obj.get('external_references', [])
            if str(ref.get('source_name', '')).startswith('mitre') and ref.get('external_id')
        ]
        if not attack_ids or not obj.get('name'):
            continue
        objects[kind][attack_ids[0]] = (obj['name'].strip(), bool(obj.get('x_mitre_deprecated')))
    return version, objects


###################################################################################################
def build_maps(framework, objects, aliases):
    """Build {file_name: {key: value}} for one framework"""
    maps = {}
    for kind, entries in objects.items():
        if not entries:
            continue

        # ID -> name, including deprecated entries so older data that references them still gets names
        maps[f'mitre_attack_{kind}_{framework}_names.yaml'] = {
            attack_id: name for attack_id, (name, _) in sorted(entries.items(), key=lambda x: id_sort_key(x[0]))
        }

        # name -> ID(s) and name -> reference(s): current entries only, and only top-level techniques
        #   (subtechnique names aren't unique, e.g., several "Local Account" subtechniques)
        ids = {}
        for attack_id, (name, deprecated) in entries.items():
            if deprecated or ('.' in attack_id):
                continue
            ids.setdefault(lookup_key(name), [])
            if attack_id not in ids[lookup_key(name)]:
                ids[lookup_key(name)].append(attack_id)
        for key, alias_ids in (aliases.get(framework, {}).get(kind, {}) or {}).items():
            alias_ids = [alias_ids] if isinstance(alias_ids, str) else list(alias_ids)
            for alias_id in alias_ids:
                if alias_id not in entries:
                    logging.warning(f'{framework} {kind} alias {key} refers to unknown ID {alias_id}')
            if key in ids:
                logging.warning(f'{framework} {kind} alias {key} is also an ATT&CK name; merging')
            ids[key] = sorted(set(ids.get(key, []) + alias_ids), key=id_sort_key)
        for key, attack_ids in ids.items():
            if len(attack_ids) > 1 and not any(key == alias for alias in (aliases.get(framework, {}).get(kind, {}) or {})):
                logging.warning(f'{framework} {kind} name {key} maps to several IDs: {attack_ids}')

        ids = dict(sorted(ids.items(), key=lambda x: x[0].lower()))
        maps[f'mitre_attack_{kind}_{framework}_ids.yaml'] = ids
        if kind in REFERENCE_PATHS:
            maps[f'mitre_attack_{kind}_{framework}_reference.yaml'] = {
                key: [reference_url(kind, attack_id) for attack_id in attack_ids] for key, attack_ids in ids.items()
            }
    return maps


def format_map(entries, header):
    """Format a map in the style of the existing files: "key": "value" or "key": [ "a", "b" ]"""
    lines = [f'# {line}' if line else '#' for line in header]
    for key, value in entries.items():
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        if isinstance(value, list):
            value_str = '[ ' + ', '.join(json.dumps(v, ensure_ascii=False) for v in value) + ' ]'
        else:
            value_str = json.dumps(value, ensure_ascii=False)
        lines.append(f'{json.dumps(key, ensure_ascii=False)}: {value_str}')
    return '\n'.join(lines) + '\n'


###################################################################################################
def main():
    parser = argparse.ArgumentParser(
        description='Generate the MITRE ATT&CK lookup dictionaries in logstash/maps from ATT&CK STIX data',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
        usage=f'{script_name} <arguments>',
    )
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Verbose output')
    parser.add_argument(
        '--version',
        dest='version',
        default='',
        metavar='<string>',
        help='ATT&CK version to use, e.g., 20.0 (default: latest)',
    )
    parser.add_argument(
        '-f',
        '--framework',
        dest='frameworks',
        action='append',
        choices=FRAMEWORKS_ALL,
        help=f"Framework(s) to generate (default: {', '.join(FRAMEWORKS_DEFAULT)})",
    )
    parser.add_argument(
        '-i',
        '--input-dir',
        dest='input_dir',
        default=None,
        metavar='<path>',
        help='Read <framework>-attack[-<version>].json from this directory instead of downloading',
    )
    parser.add_argument(
        '-o',
        '--output-dir',
        dest='output_dir',
        default=OUTPUT_DIR_DEFAULT,
        metavar='<path>',
        help=f'Output directory (default: {OUTPUT_DIR_DEFAULT})',
    )
    parser.add_argument(
        '-a',
        '--aliases',
        dest='aliases',
        default=None,
        metavar='<path>',
        help='YAML file of additional aliases, in the same structure as ALIASES (merged over the built-in ones)',
    )
    parser.add_argument(
        '--check',
        dest='check',
        action='store_true',
        help='Report which files would change without writing them (exit 1 if any would)',
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format='%(levelname)s: %(message)s',
    )

    aliases = {framework: {kind: dict(entries) for kind, entries in kinds.items()} for framework, kinds in ALIASES.items()}
    if args.aliases:
        with open(args.aliases, 'r', encoding='utf-8') as f:
            for framework, kinds in (yaml.safe_load(f) or {}).items():
                for kind, entries in (kinds or {}).items():
                    aliases.setdefault(framework, {}).setdefault(kind, {}).update(entries or {})

    changed = []
    for framework in args.frameworks or FRAMEWORKS_DEFAULT:
        version, objects = parse_bundle(load_bundle(framework, args.version, args.input_dir))
        header = [
            f'Generated by scripts/{script_name} from MITRE ATT&CK {framework} STIX data, version {version}.',
            f'Do not edit by hand; to add names ATT&CK doesn\'t use, edit ALIASES in scripts/{script_name}.',
            '',
        ]
        for file_name, entries in build_maps(framework, objects, aliases).items():
            content = format_map(entries, header)
            path = os.path.join(args.output_dir, file_name)
            previous = None
            if os.path.isfile(path):
                with open(path, 'r', encoding='utf-8') as f:
                    previous = f.read()
            if content == previous:
                logging.info(f'{file_name}: unchanged')
                continue
            changed.append(file_name)
            print(f"{file_name}: {'would change' if args.check else 'written'} ({len(entries)} entries)")
            if not args.check:
                os.makedirs(args.output_dir, exist_ok=True)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)

    if not changed:
        print('All files up to date')
    return 1 if (args.check and changed) else 0


if __name__ == '__main__':
    sys.exit(main())
