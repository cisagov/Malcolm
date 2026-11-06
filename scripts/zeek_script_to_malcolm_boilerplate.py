#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

#
# This script takes as input the filenames of one or more .zeek scripts which
# contain records (see https://docs.zeek.org/en/master/script-reference/types.html#type-record).
#
# The scripts are parsed into their constituent records and &log fields.
#
# Each record is then printed out in the formats used by Malcolm for parsing and defining Zeek logs:
# - Logstash (https://idaholab.github.io/Malcolm/docs/contributing-logstash.html#LogstashZeek), for ./logstash/pipelines/zeek/1001_zeek_parse.conf
# - Arkime (https://idaholab.github.io/Malcolm/docs/contributing-new-log-fields.html#NewFields), for ./arkime/etc/config.ini
# - OpenSearch tndex templates (https://idaholab.github.io/Malcolm/docs/contributing-new-log-fields.html#NewFields), for ./dashboards/templates/composable/component/zeek*.json
#
# The logstash/scripts/logstash-start.sh container startup script should automatically fix any issues
#   with parsing the Zeek tab delimiter (e.g., converting spaces in the `dissect` and `split` filters to tabs)
#

import argparse
import io
import json
import logging
import os
import sys
import zeekscript
import operator
import malcolm_utils
from collections import defaultdict
from datetime import datetime
from slugify import slugify

###################################################################################################
args = None
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

ZEEK_DELIMITER_CHAR = '\t'

ZEEK_COMMON_FIELDS = (
    'ts',
    'uid',
    'fuid',
    'is_orig',
    'orig_h',
    'orig_p',
    'orig_l2_addr',
    'resp_h',
    'resp_p',
    'resp_l2_addr',
    'drop_orig_h',
    'drop_orig_p',
    'drop_resp_h',
    'drop_resp_p',
    'proto',
    'service',
    'user',
    'password',
    'community_id',
)

ZEEK_TO_ARKIME_TYPES = defaultdict(lambda: "termfield")
for fType in ('count', 'int', 'port'):
    ZEEK_TO_ARKIME_TYPES[fType] = 'integer'

ZEEK_TO_INDEX_TEMPLATE_TYPES = defaultdict(lambda: "keyword")
ZEEK_TO_INDEX_TEMPLATE_TYPES['int'] = 'integer'
ZEEK_TO_INDEX_TEMPLATE_TYPES['count'] = 'long'
ZEEK_TO_INDEX_TEMPLATE_TYPES['time'] = 'date'
ZEEK_TO_INDEX_TEMPLATE_TYPES['double'] = 'float'
ZEEK_TO_INDEX_TEMPLATE_TYPES['interval'] = 'float'

# hate to use a global for this but not sure how to get the script from the node
current_script = None

# Used as a predicate to filter nodes during tree traversal.
# see https://github.com/zeek/zeekscript/blob/4a3512dd114e2709d6738016176c27a65f3f1492/zeekscript/node.py#L157


# This Node is a "create_stream" expression, e.g.:
#   Log::create_stream(ICSNPP_OPCUA_Binary::LOG, [$columns=OPCUA_Binary::Info, $path="opcua-binary"])
def IsCreateStreamExprNode(Node):
    try:
        return (
            (Node.name() == 'expr')
            and current_script.get_content(*Node.script_range())
            .decode('utf-8')
            .lower()
            .startswith('log::create_stream')
            and any([c for c in Node.nonerr_children if c.name() == 'expr_list'])
        )
    except (AttributeError, IndexError):
        return False

    return False


# This Node is an expression that looks like:
#   $columns=OPCUA_Binary::VariantData
def IsColumnsExprNode(Node):
    try:
        return (Node.name() == 'id') and (
            current_script.get_content(*Node.script_range()).decode('utf-8').lower() == 'columns'
        )
    except (AttributeError, IndexError):
        return False


# This Node is an expression that looks like:
#   $path="opcua-binary"
def IsPathExprNode(Node):
    try:
        return (Node.name() == 'id') and (
            current_script.get_content(*Node.script_range()).decode('utf-8').lower() == 'path'
        )
    except (AttributeError, IndexError):
        return False


# This Node is a "create_stream" expression LIST node, e.g.:
#   $columns=OPCUA_Binary::Info, $path="opcua-binary"
def IsCreateStreamExprStreamListNode(Node):
    try:
        if Node.name() == 'expr_list':
            for exprNode in [n for n in Node.nonerr_children if (n.name() == 'expr') and (len(n.nonerr_children) > 0)]:
                if any([p for p in exprNode.nonerr_children if IsColumnsExprNode(p)]):
                    return True

    except (AttributeError, IndexError):
        return False

    return False


# This Node is a "record" node, e.g.:
#   type OPCUA_Binary::CreateSubscription: record
def IsRecordNode(Node):
    return Node.name() == 'type_decl'


# This Node is a "logged field" node, e.g.:
#   ts : time &log;
def IsLoggedFieldNode(Node):
    if Node.name() == 'type_spec':
        try:
            for attrNode in [
                a
                for a in [n for n in Node.nonerr_children if n.name() == 'attr_list'][0].nonerr_children
                if a.name() == 'attr'
            ]:
                if any([c.token() for c in attrNode.nonerr_children if not c.is_named and c.token() == '&log']):
                    return True
        except (AttributeError, IndexError):
            return False

    return False


def NestProperties(FlatProps):
    nested = {}
    for dotted_key, value in FlatProps.items():
        parts = dotted_key.split(".")
        current = nested
        for part in parts[:-1]:
            current = current.setdefault(part, {}).setdefault("properties", {})
        current[parts[-1]] = value
    return nested



def _parse_arguments(argv=None):
    nowTimeStr = datetime.now().strftime("%Y%m%d-%H%M%S")

    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'Parse Zeek .script files and generate boilerplate for a Malcolm boilerplate for parsing and defining those Zeek logs.',
                'see https://idaholab.github.io/Malcolm/docs/contributing-guide.html',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
        usage='{} <arguments>'.format(script_name),
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=malcolm_utils.get_verbosity_env_var_count("VERBOSITY"),
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '--expand-id',
        dest='expandId',
        action='store_true',
        help='Expand id field to orig_h, orig_p, resp_h and resp_p',
    )
    parser.add_argument(
        '--no-expand-id',
        dest='expandId',
        action='store_false',
        help='Do not expand id field to orig_h, orig_p, resp_h and resp_p',
    )
    parser.set_defaults(expandId=True)
    parser.add_argument(
        '-c',
        '--include-cst',
        dest='includeCst',
        action='store_true',
        help='Include CST nodes',
    )
    parser.add_argument(
        '--no-include-cst',
        dest='includeCst',
        action='store_false',
        help='Do not include CST nodes',
    )
    parser.set_defaults(includeCst=False)
    parser.add_argument(
        '-i',
        '--input',
        dest='input',
        nargs='*',
        type=str,
        default=None,
        required=False,
        help=".zeek script(s) to parse",
    )
    parser.add_argument(
        '-t',
        '--tags',
        dest='tags',
        nargs='*',
        type=str,
        default=[],
        required=False,
        help="Tags to add to parsed events",
    )
    parser.add_argument(
        '-p',
        '--proto',
        dest='protocol',
        type=str,
        default="",
        required=False,
        help="Value for proto field to add to parsed events (e.g., tcp)",
    )
    parser.add_argument(
        '-s',
        '--service',
        dest='service',
        type=str,
        default="",
        required=False,
        help="Value for service field to add to parsed events (e.g., http)",
    )
    parser.add_argument(
        '-u',
        '--url',
        dest='url',
        type=str,
        default="",
        required=False,
        help="Value for reference URL for the filter's comments",
    )
    parser.add_argument(
        '-l',
        '--logstash',
        dest='logstashOutFile',
        type=str,
        default=f"{nowTimeStr}.logstash.conf",
        required=False,
        help="Filename to which the Logstash filter boilerplate will be written",
    )
    parser.add_argument(
        '-a',
        '--arkime',
        dest='arkimeOutFile',
        type=str,
        default=f"{nowTimeStr}.arkime.ini",
        required=False,
        help="Filename to which the Arkime config.ini boilerplate will be written",
    )
    parser.add_argument(
        '-x',
        '--index',
        dest='indexOutFile',
        type=str,
        default=f"{nowTimeStr}.template.json",
        required=False,
        help="Filename to which the OpenSearch index template boilerplate will be written",
    )
    parser.add_argument(
        '-j',
        '--json',
        dest='jsonOutFile',
        type=str,
        default="",
        required=False,
        help="Filename to which the intermediate structures' JSON be written",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)

    return args


def _slug_script_content(node):
    """Slugify one parsed Zeek syntax node without changing input case rules."""
    return slugify(current_script.get_content(*node.script_range()).decode('utf-8')).replace('-', '_')


def _stream_column_or_path(expr_list, predicate, include_cst):
    for node, _ in expr_list.traverse(include_cst=include_cst, predicate=predicate):
        sibling = node
        while (sibling := sibling.next_sibling):
            if sibling.name() == 'expr':
                return _slug_script_content(sibling)
    return None


def _discover_stream_paths(include_cst):
    """Find explicit Log::create_stream column-to-log-path mappings."""
    paths = {}
    for stream, _ in current_script.root.traverse(
        include_cst=include_cst, predicate=IsCreateStreamExprNode,
    ):
        for args_node, _ in stream.traverse(
            include_cst=include_cst, predicate=IsCreateStreamExprStreamListNode,
        ):
            column = _stream_column_or_path(args_node, IsColumnsExprNode, include_cst)
            path = _stream_column_or_path(args_node, IsPathExprNode, include_cst)
            if column and path:
                paths[column] = path
    return paths


def _first_script_node(node, name, include_cst):
    return next((item for item, _ in node.traverse(include_cst=include_cst) if item.name() == name), None)


def _record_name(type_declaration, include_cst):
    identifier = _first_script_node(type_declaration, 'id', include_cst)
    return _slug_script_content(identifier) if identifier is not None else None


def _logged_field(type_info, include_cst):
    """Convert an &log declaration to its Zeek field name and type."""
    identifier = _first_script_node(type_info, 'id', include_cst)
    field_type = _first_script_node(type_info, 'type', include_cst)
    if identifier is None or field_type is None:
        return None
    # Preserve the original Zeek type normalization: `conn_id` maps to
    # `conn-id` in the intermediate JSON, while field names use underscores.
    return {
        'name': _slug_script_content(identifier),
        'type': slugify(current_script.get_content(*field_type.script_range()).decode('utf-8').lower()),
    }


def _record_logged_fields(type_decl, include_cst, expand_id):
    fields = []
    for field, _ in type_decl.traverse(include_cst=include_cst, predicate=IsLoggedFieldNode):
        info = _logged_field(field, include_cst)
        if not info:
            continue
        if expand_id and info['type'] == 'conn-id':
            fields.extend([
                {'name': 'orig_h', 'type': 'addr'}, {'name': 'orig_p', 'type': 'port'},
                {'name': 'resp_h', 'type': 'addr'}, {'name': 'resp_p', 'type': 'port'},
            ])
        else:
            fields.append(info)
    return fields


def _script_namespace(raw_source):
    """Find a simple file-level Zeek module declaration (if one exists)."""
    import re

    matched = re.search(rb'(?m)^\s*module\s+([A-Za-z_][\w:]*)\s*;', raw_source)
    return slugify(matched.group(1).decode('utf-8')).replace('-', '_') if matched else None


def _resolve_stream_path(name, namespace, local_paths, global_paths):
    """Prefer a module-qualified stream, then file-local and global matches."""
    qualified = f'{namespace}_{name}' if namespace else name
    # A module-qualified mapping is unambiguous across files. File-local
    # unqualified mappings take priority over unrelated streams elsewhere.
    return (
        local_paths.get(qualified) or local_paths.get(name)
        or global_paths.get(qualified) or global_paths.get(name)
    )


def _parse_sources(sources, include_cst, expand_id):
    """Parse each script once; resolve streams by module and source file."""
    global current_script
    parsed = []
    global_paths = {}
    for source in sources or ():
        with open(source, 'rb') as stream:
            content = stream.read()
        current_script = zeekscript.Script(io.BytesIO(content))
        if not current_script.parse() or current_script.has_error():
            logging.critical(f'Parsing {os.path.basename(source)}: "{current_script.get_error()}"')
            continue
        logging.debug(f'Parsed {os.path.basename(source)}')
        local_paths = _discover_stream_paths(include_cst)
        namespace = _script_namespace(content)
        parsed.append((source, current_script, namespace, local_paths))
        for key, value in local_paths.items():
            global_paths.setdefault(key, value)

    records = []
    for source, script, namespace, paths in parsed:
        current_script = script
        for type_decl, _ in script.root.traverse(include_cst=include_cst, predicate=IsRecordNode):
            type_name = _record_name(type_decl, include_cst)
            if type_name:
                path = _resolve_stream_path(type_name, namespace, paths, global_paths)
                logging.debug(f'Found record {type_name} ({path or ""})')
                fields = _record_logged_fields(type_decl, include_cst, expand_id)
                for field in fields:
                    logging.debug(f"Found field {type_name}.{field['name']} ({field['type']})")
                records.append({
                    'name': type_name, 'path': path, 'fields': fields,
                    '_source': os.path.basename(source),
                })
    records.sort(key=operator.itemgetter('name'))
    return records


def _write_records_json(records, args):
    # write output file(s)

    if args.jsonOutFile:
        with open(args.jsonOutFile, "w") as f:
            f.write(
                json.dumps(
                    {
                        "records": [{k: v for k, v in record.items() if not k.startswith('_')} for record in records],
                    },
                    indent=2,
                )
            )



def _write_logstash(records, args):
    # output boilerplate Logstash filter for use in Malcolm
    with open(args.logstashOutFile, "w") as f:
        print('filter {', file=f)
        for record in [r for r in records if len(r["fields"]) > 0]:
            # default to the record's log path, fall back to the slugified record name
            rName = record['path'] if ('path' in record) and record['path'] else record['name']
            rFieldsZip = ', '.join(["'" + x['name'] + "'" for x in record['fields']])
            rFieldsDissect = ZEEK_DELIMITER_CHAR.join([f'%{{[zeek_cols][{x["name"]}]}}' for x in record['fields']])
            tags = ', '.join(['"' + x + '"' for x in args.tags])
            print(
                '\n'.join(
                    (
                        '',
                        f'  if ([log_source] == "{rName}") {{',
                        '    #############################################################################################################################',
                        f'    # {rName}.log',
                        f'    # {record.get('_source', 'unknown')} ({args.url})',
                        '',
                        '    if ("_jsonparsesuccess" not in [tags]) {',
                        '      dissect {',
                        f'        id => "dissect_zeek_{rName}"',
                        '        mapping => {',
                        f'          "[message]" => "{rFieldsDissect}"',
                        '        }',
                        '      }',
                        '',
                        '      if ("_dissectfailure" in [tags]) {',
                        '        mutate {',
                        f'          id => "mutate_split_zeek_{rName}"',
                        f'          split => {{ "[message]" => "{ZEEK_DELIMITER_CHAR}" }}',
                        '        }',
                        '        ruby {',
                        f'          id => "ruby_zip_zeek_{rName}"',
                        f'          init => "@zeek_{rName}_field_names = [ {rFieldsZip} ]"',
                        f"          code => \"event.set('[zeek_cols]', @zeek_{rName}_field_names.zip(event.get('[message]')).to_h)\"",
                        '        }',
                        '      }',
                        '    }',
                        '',
                        '    mutate {',
                        f'      id => "mutate_add_fields_zeek_{rName}"',
                        '      add_field => {',
                        f'        "[zeek_cols][proto]" => "{args.protocol}"',
                        f'        "[zeek_cols][service]" => "{args.service}"',
                        '      }',
                        f'      add_tag => [ {tags} ]' if tags else '',
                        '    }',
                        '  }',
                        '',
                    )
                ),
                file=f,
            )
        print('\n'.join(('}', '')), file=f)



def _write_arkime(records, args):
    # output boilerplate Arkime definitions for use in Malcolm
    with open(args.arkimeOutFile, "w") as f:
        for record in [r for r in records if len(r["fields"]) > 0]:
            # default to the record's log path, fall back to the slugified record name
            rName = record['path'] if ('path' in record) and record['path'] else record['name']
            print(f"# {rName}.log", file=f)
            print(f"# {args.url}", file=f)
            # https://github.com/cisagov/ICSNPP
            for field in [f for f in record['fields'] if f['name'] not in ZEEK_COMMON_FIELDS]:
                print(
                    f"zeek.{rName}.{field['name']}=db:zeek.{rName}.{field['name']};group:zeek_{rName};kind:{ZEEK_TO_ARKIME_TYPES[field['type']]};viewerOnly:true;friendly:{field['name']};help:{field['name']}",
                    file=f,
                )
            print("", file=f)

        print("[custom-views]", file=f)
        for record in [r for r in records if len(r["fields"]) > 0]:
            rName = record['path'] if ('path' in record) and record['path'] else record['name']
            rFields = ','.join(
                [f"zeek.{rName}.{f['name']}" for f in record['fields'] if f['name'] not in ZEEK_COMMON_FIELDS]
            )
            print(
                f"zeek_{rName}=require:zeek.{rName};title:Zeek {rName}.log;fields:{rFields}",
                file=f,
            )



def _write_index_template(records, args):
    # output boilerplate OpenSearch index template fields for use in Malcolm
    flatFields = {}
    with open(args.indexOutFile, "w") as f:
        for record in [r for r in records if len(r["fields"]) > 0]:
            # default to the record's log path, fall back to the slugified record name
            rName = record['path'] if ('path' in record) and record['path'] else record['name']
            for field in [f for f in record['fields'] if f['name'] not in ZEEK_COMMON_FIELDS]:
                flatFields[f"zeek.{rName}.{field['name']}"] = {"type": ZEEK_TO_INDEX_TEMPLATE_TYPES[field['type']]}
        f.write(
            json.dumps(
                {"template": {"mappings": {"properties": NestProperties(flatFields)}}},
                indent=2,
            )
        )


def main(argv=None):
    global args
    args = _parse_arguments(argv)
    # set up logging
    args.verbose = malcolm_utils.set_logging(os.getenv("LOGLEVEL", ""), args.verbose, set_traceback_limit=True)
    logging.debug(os.path.join(script_path, script_name))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

    records = _parse_sources(args.input, args.includeCst, args.expandId)
    if args.jsonOutFile:
        _write_records_json(records, args)
    _write_logstash(records, args)
    _write_arkime(records, args)
    _write_index_template(records, args)




###################################################################################################
if __name__ == '__main__':
    main()
