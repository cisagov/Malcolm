#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# This script takes as input the filenames of one or more .zeek scripts which
# contain records (see https://docs.zeek.org/en/master/script-reference/types.html#type-record).
#
# The scripts are parsed into their constitutent records and &log fields.
#
# Each record is then printed out in the formats used by Malcolm for parsing and defining Zeek logs:
# - Logstash (https://idaholab.github.io/Malcolm/docs/contributing-logstash.html#LogstashZeek), for ./logstash/pipelines/zeek/11_zeek_parse.conf
# - Arkime (https://idaholab.github.io/Malcolm/docs/contributing-new-log-fields.html#NewFields), for ./arkime/etc/config.ini
# - OpenSearch tndex templates (https://idaholab.github.io/Malcolm/docs/contributing-new-log-fields.html#NewFields), for ./dashboards/templates/composable/component/zeek*.json
#
# For Logstash boilerplate, pay close attention to the comment in the logstash filter:
#    # zeek's default delimiter is a literal tab, MAKE SURE YOUR EDITOR DOESN'T SCREW IT UP
# If you are copy/pasting, ensure your editor doesn't lose the TAB characters.
#

import argparse
import io
import json
import logging
import os
import sys
import zeekscript
import operator
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


###################################################################################################
# main
def main():
    global args
    global current_script

    nowTimeStr = datetime.now().strftime("%Y%m%d-%H%M%S")

    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'Parse Zeek .script files and generate boilerplate for a Malcolm boilerplate for parsing and defining those Zeek logs.',
                'see https://idaholab.github.io/Malcolm/docs/contributing-guide.html',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage='{} <arguments>'.format(script_name),
    )
    parser.add_argument('--verbose', '-v', action='count', default=1, help='Increase verbosity (e.g., -v, -vv, etc.)')
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
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    # set up logging
    args.verbose = logging.ERROR - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.debug(os.path.join(script_path, script_name))
    logging.debug("Arguments: {}".format(sys.argv[1:]))
    logging.debug("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    # this array will hold all of the different log types until the end when we print them out
    records = []
    recordsPathMap = {}

    # Parse all of the .zeek scripts TWICE: once to find the mapping of record names to .log paths,
    # and a second time to get the fields for those recoreds. Yeah, it's inefficient, but this
    # is something you do once in a blue moon so I don't care.
    for parseLoop in (0, 1):
        for val in args.input if args.input else ():
            contents = None
            with open(val, 'rb') as f:
                contents = f.read()
            current_script = zeekscript.Script(io.BytesIO(contents))
            if current_script.parse() and not current_script.has_error():
                logging.debug(f'Parsed {os.path.basename(val)}')

                if parseLoop == 0:
                    # find create_stream expression list nodes to map record names to .log paths
                    #   e.g.:           Log::create_stream(ICSNPP_OPCUA_Binary::LOG, [$columns=OPCUA_Binary::Info, $path="opcua-binary"]);
                    #   would yield:    "opcua_binary_info": "opcua-binary"
                    for createStreamNode, indent in current_script.root.traverse(
                        include_cst=args.includeCst,
                        predicate=IsCreateStreamExprNode,
                    ):
                        # within that list of expressions for that statement find the
                        # expression which itself is the list of $columns and $path
                        for childNode, indentToo in createStreamNode.traverse(
                            include_cst=args.includeCst,
                            predicate=IsCreateStreamExprStreamListNode,
                        ):
                            # now, within this list, get the slugified version of the record name
                            # (from $columns) and the log filename (from $path)
                            columnName = None
                            logPath = None

                            for argNode, indentThree in childNode.traverse(
                                include_cst=args.includeCst,
                                predicate=IsColumnsExprNode,
                            ):
                                sib = argNode
                                while (sib := sib.next_sibling) and (not columnName):
                                    if sib.name() == "expr":
                                        columnName = slugify(
                                            current_script.get_content(*sib.script_range()).decode('utf-8')
                                        ).replace('-', '_')

                            for argNode, indentThree in childNode.traverse(
                                include_cst=args.includeCst,
                                predicate=IsPathExprNode,
                            ):
                                sib = argNode
                                while (sib := sib.next_sibling) and (not logPath):
                                    if sib.name() == "expr":
                                        logPath = slugify(
                                            current_script.get_content(*sib.script_range()).decode('utf-8')
                                        ).replace('-', '_')

                            if columnName and logPath:
                                # I cannot believe it. We did it.
                                recordsPathMap[columnName] = logPath

                if parseLoop == 1:
                    # find each "record" node
                    for typeDeclNode, _ in current_script.root.traverse(
                        include_cst=args.includeCst,
                        predicate=IsRecordNode,
                    ):
                        # determine the name of the record node
                        # this isn't *exactly* going to match the acutal filename
                        # of the .log file, but it'll be close enough for a good start
                        typeName = None
                        try:
                            typeName = slugify(
                                current_script.get_content(
                                    *[
                                        n
                                        for n, _ in typeDeclNode.traverse(
                                            include_cst=args.includeCst,
                                        )
                                        if n.name() == 'id'
                                    ][0].script_range()
                                ).decode('utf-8')
                            ).replace('-', '_')
                        except (AttributeError, IndexError):
                            pass

                        # process the fields belonging to this record
                        if typeName:
                            logging.debug(f'Found record {typeName} ({recordsPathMap.get(typeName, "")})')
                            record = {}
                            record["name"] = typeName
                            record["path"] = recordsPathMap.get(typeName, None)
                            record["fields"] = []

                            # find each "logged field" inside this record
                            for typeInfoNode, indent in typeDeclNode.traverse(
                                include_cst=args.includeCst,
                                predicate=IsLoggedFieldNode,
                            ):
                                # determine the field's name and type
                                fieldName = None
                                fieldType = None
                                try:
                                    fieldName = slugify(
                                        current_script.get_content(
                                            *[
                                                n
                                                for n, _ in typeInfoNode.traverse(
                                                    include_cst=args.includeCst,
                                                )
                                                if n.name() == 'id'
                                            ][0].script_range()
                                        ).decode('utf-8')
                                    ).replace('-', '_')
                                    fieldType = slugify(
                                        current_script.get_content(
                                            *[
                                                n
                                                for n, _ in typeInfoNode.traverse(
                                                    include_cst=args.includeCst,
                                                )
                                                if n.name() == 'type'
                                            ][0].script_range()
                                        )
                                        .decode('utf-8')
                                        .lower()
                                    )
                                except (AttributeError, IndexError):
                                    pass

                                # if we found the name and type, add it to the record
                                if fieldName and fieldType:
                                    logging.debug(f'Found field {typeName}.{fieldName} ({fieldType})')
                                    if args.expandId and (fieldType == "conn-id"):
                                        # conn-id actually is a 4-tuple
                                        record["fields"] = record["fields"] + [
                                            {"name": "orig_h", "type": "addr"},
                                            {"name": "orig_p", "type": "port"},
                                            {"name": "resp_h", "type": "addr"},
                                            {"name": "resp_p", "type": "port"},
                                        ]
                                    else:
                                        record["fields"].append({"name": fieldName, "type": fieldType})

                            # this record has been parsed, add it to the final list
                            records.append(record)

            else:
                logging.error(f'Parsing {os.path.basename(val)}: "{current_script.get_error()}"')

    records.sort(key=operator.itemgetter('name'))

    # write output file(s)

    if args.jsonOutFile:
        with open(args.jsonOutFile, "w") as f:
            f.write(
                json.dumps(
                    {
                        "records": records,
                    },
                    indent=2,
                )
            )

    # output boilerplate Logstash filter for use in Malcolm
    with open(args.logstashOutFile, "w") as f:
        for record in [r for r in records if len(r["fields"]) > 0]:
            # default to the record's log path, fall back to the slugified record name
            rName = record['path'] if ('path' in record) and record['path'] else record['name']
            rFieldsZip = ', '.join(["'" + x['name'] + "'" for x in record['fields']])
            rFieldsDissect = ZEEK_DELIMITER_CHAR.join([f'%{{[zeek_cols][{x["name"]}]}}' for x in record['fields']])
            tags = ', '.join(['"' + x + '"' for x in args.tags])
            print(
                '\n'.join(
                    (
                        f'}} else if ([log_source] == "{rName}") {{',
                        f'  #############################################################################################################################',
                        f'  # {rName}.log',
                        f'  # {os.path.basename(val)} ({args.url})',
                        '',
                        f'  dissect {{',
                        f'    id => "dissect_zeek_{rName}"',
                        f"    # zeek's default delimiter is a literal tab, MAKE SURE YOUR EDITOR DOESN'T SCREW IT UP",
                        f'    mapping => {{',
                        f'      "[message]" => "{rFieldsDissect}"',
                        f'    }}',
                        f'  }}',
                        '',
                        f'  if ("_dissectfailure" in [tags]) {{',
                        f'    mutate {{',
                        f'      id => "mutate_split_zeek_{rName}"',
                        f"      # zeek's default delimiter is a literal tab, MAKE SURE YOUR EDITOR DOESN'T SCREW IT UP",
                        f'      split => {{ "[message]" => "{ZEEK_DELIMITER_CHAR}" }}',
                        f'    }}',
                        f'    ruby {{',
                        f'      id => "ruby_zip_zeek_{rName}"',
                        f'      init => "$zeek_{rName}_field_names = [ {rFieldsZip} ]"',
                        f"      code => \"event.set('[zeek_cols]', $zeek_{rName}_field_names.zip(event.get('[message]')).to_h)\"",
                        f'    }}',
                        f'  }}',
                        '',
                        f'  mutate {{',
                        f'    id => "mutate_add_fields_zeek_{rName}"',
                        f'    add_field => {{',
                        f'      "[zeek_cols][proto]" => "{args.protocol}"',
                        f'      "[zeek_cols][service]" => "{args.service}"',
                        f'    }}',
                        f'    add_tag => [ {tags} ]' if tags else '',
                        f'  }}',
                        '',
                    )
                ),
                file=f,
            )

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
                    f"zeek.{rName}.{field['name']}=db:zeek.{rName}.{field['name']};group:zeek_{rName};kind:{ZEEK_TO_ARKIME_TYPES[field['type']]};friendly:{field['name']};help:{field['name']}",
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

    # output boilerplate OpenSearch index template fields for use in Malcolm
    mappings = {"template": {"mappings": {"properties": {}}}}
    with open(args.indexOutFile, "w") as f:
        for record in [r for r in records if len(r["fields"]) > 0]:
            # default to the record's log path, fall back to the slugified record name
            rName = record['path'] if ('path' in record) and record['path'] else record['name']
            for field in [f for f in record['fields'] if f['name'] not in ZEEK_COMMON_FIELDS]:
                mappings["template"]["mappings"]["properties"][f"zeek.{rName}.{field['name']}"] = {
                    "type": ZEEK_TO_INDEX_TEMPLATE_TYPES[field['type']]
                }
        f.write(
            json.dumps(
                mappings,
                indent=2,
            )
        )


###################################################################################################
if __name__ == '__main__':
    main()
