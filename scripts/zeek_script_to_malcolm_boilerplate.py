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
# - Logstash parse filters, for a new ./logstash/pipelines/zeek/10xx_zeek_<parser>.conf file
#   (the output also lists any `time` fields to add to ./logstash/pipelines/zeek/1400_zeek_convert.conf)
# - Arkime field definitions and session views, for ./arkime/etc/config.ini
# - OpenSearch index template mappings, for ./dashboards/templates/composable/component/zeek.json or zeek_ot.json
# - Arkime WISE value-action field names, for the allFields array in ./arkime/wise/source.zeeklogs.js
#
# The output is boilerplate: a starting point to be reviewed and adjusted, not a finished integration.
#   See https://idaholab.github.io/Malcolm/docs/contributing-zeek-parser.html for the whole process.
#
# The logstash/scripts/logstash-start.sh container startup script should automatically fix any issues
#   with parsing the Zeek tab delimiter (e.g., converting spaces in the `dissect` and `split` filters to tabs)
#
# Requirements: the zeekscript and python-slugify Python packages, and malcolm_utils.py (found alongside
#   this script in Malcolm's ./scripts directory)
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
# Zeek's int and count are both 64-bit, so map both to long: an integer (32-bit) mapping rejects
#   any document whose value doesn't fit, rather than just that field. Narrow a mapping by hand
#   only when the field's values are known to fit.
ZEEK_TO_INDEX_TEMPLATE_TYPES['int'] = 'long'
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


###################################################################################################
# main
def main():
    global args
    global current_script

    nowTimeStr = datetime.now().strftime("%Y%m%d-%H%M%S")

    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'Parse Zeek .zeek scripts and generate Malcolm boilerplate for parsing and defining the logs they write.',
                'see https://idaholab.github.io/Malcolm/docs/contributing-zeek-parser.html',
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
        '-w',
        '--wise',
        dest='wiseOutFile',
        type=str,
        default=f"{nowTimeStr}.wise.txt",
        required=False,
        help="Filename to which the Arkime WISE allFields boilerplate will be written",
    )
    parser.add_argument(
        '-g',
        '--arkime-group',
        dest='arkimeGroup',
        type=str,
        default="",
        required=False,
        help="Arkime field group for all generated fields (e.g., zeek_iccp); default is one group per log (zeek_<log>)",
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
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)

    # set up logging
    args.verbose = malcolm_utils.set_logging(os.getenv("LOGLEVEL", ""), args.verbose, set_traceback_limit=True)
    if not args.input:
        parser.print_help()
        sys.exit(2)
    if not args.service:
        logging.warning(
            'No --service given: the Logstash boilerplate won\'t set [zeek_cols][service], which Malcolm uses for network.protocol'
        )
    logging.debug(os.path.join(script_path, script_name))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

    # this array will hold all of the different log types until the end when we print them out
    records = []
    recordsPathMap = {}

    # Parse all of the .zeek scripts TWICE: once to find the mapping of record names to .log paths,
    # and a second time to get the fields for those records. Yeah, it's inefficient, but this
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
                                        columnName = current_script.get_content(*sib.script_range()).decode('utf-8')

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
                                # $columns may or may not be module-qualified (ICCP::Info vs. Info), independently
                                #   of how the record itself is declared, so index both forms
                                for colName in (columnName, columnName.split('::')[-1]):
                                    recordsPathMap[slugify(colName).replace('-', '_')] = logPath

                if parseLoop == 1:
                    # find each "record" node
                    for typeDeclNode, _ in current_script.root.traverse(
                        include_cst=args.includeCst,
                        predicate=IsRecordNode,
                    ):
                        # determine the name of the record node
                        # this isn't *exactly* going to match the actual filename
                        # of the .log file, but it'll be close enough for a good start
                        typeName = None
                        shortTypeName = None
                        try:
                            typeId = current_script.get_content(
                                *[
                                    n
                                    for n, _ in typeDeclNode.traverse(
                                        include_cst=args.includeCst,
                                    )
                                    if n.name() == 'id'
                                ][0].script_range()
                            ).decode('utf-8')
                            typeName = slugify(typeId).replace('-', '_')
                            shortTypeName = slugify(typeId.split('::')[-1]).replace('-', '_')
                        except (AttributeError, IndexError):
                            pass

                        # process the fields belonging to this record
                        if typeName:
                            logging.debug(f'Found record {typeName} ({recordsPathMap.get(typeName, "")})')
                            record = {}
                            record["name"] = typeName
                            record["path"] = recordsPathMap.get(typeName, recordsPathMap.get(shortTypeName, None))
                            record["script"] = os.path.basename(val)
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
                            if record["fields"] and not record["path"]:
                                logging.warning(
                                    f'No Log::create_stream $path found for record {typeName} ({record["script"]}); '
                                    f'using "{typeName}" as its log name. Check the generated log_source, field '
                                    f'prefixes and plugin IDs, or ignore this record if it isn\'t written to a log.'
                                )
                            records.append(record)

            else:
                logging.critical(f'Parsing {os.path.basename(val)}: "{current_script.get_error()}"')

    # only records with &log fields are logs; sort them by the name of the log they write
    records = [r for r in records if len(r["fields"]) > 0]
    for record in records:
        # default to the record's log path, fall back to the slugified record name
        record["log"] = record["path"] if record.get("path") else record["name"]
    records.sort(key=operator.itemgetter('log'))

    # write output file(s)
    if args.jsonOutFile:
        with open(args.jsonOutFile, "w") as f:
            f.write(json.dumps({"records": records}, indent=2))
    with open(args.logstashOutFile, "w") as f:
        WriteLogstash(records, f)
    with open(args.arkimeOutFile, "w") as f:
        WriteArkime(records, f)
    with open(args.indexOutFile, "w") as f:
        WriteIndexTemplate(records, f)
    with open(args.wiseOutFile, "w") as f:
        WriteWise(records, f)

    for outFile in (args.logstashOutFile, args.arkimeOutFile, args.indexOutFile, args.wiseOutFile):
        logging.info(f'Wrote {outFile}')


###################################################################################################
# fields that Malcolm normalizes in common for every Zeek log, so they don't need per-log definitions
def LoggedFields(record):
    return [f for f in record['fields'] if f['name'] not in ZEEK_COMMON_FIELDS]


###################################################################################################
# boilerplate Logstash parse filters, for ./logstash/pipelines/zeek/10xx_zeek_<parser>.conf
def WriteLogstash(records, f):
    tags = ', '.join(['"' + x + '"' for x in args.tags])
    addFields = [(k, v) for k, v in (('proto', args.protocol), ('service', args.service)) if v]
    print('filter {', file=f)
    for record in records:
        rName = record['log']
        rFieldsZip = ', '.join(["'" + x['name'] + "'" for x in record['fields']])
        rFieldsDissect = ZEEK_DELIMITER_CHAR.join([f'%{{[zeek_cols][{x["name"]}]}}' for x in record['fields']])
        lines = [
            '',
            f'  if ([log_source] == "{rName}") {{',
            f'    #############################################################################################################################',
            f'    # {rName}.log',
            f'    # {record["script"]} ({args.url})' if args.url else f'    # {record["script"]}',
            '',
            f'    if ("_jsonparsesuccess" not in [tags]) {{',
            f'      dissect {{',
            f'        id => "dissect_zeek_{rName}"',
            f'        mapping => {{',
            f'          "[message]" => "{rFieldsDissect}"',
            f'        }}',
            f'      }}',
            '',
            f'      if ("_dissectfailure" in [tags]) {{',
            f'        mutate {{',
            f'          id => "mutate_split_zeek_{rName}"',
            f'          split => {{ "[message]" => "{ZEEK_DELIMITER_CHAR}" }}',
            f'        }}',
            f'        ruby {{',
            f'          id => "ruby_zip_zeek_{rName}"',
            f'          init => "@zeek_{rName}_field_names = [ {rFieldsZip} ]"',
            f"          code => \"event.set('[zeek_cols]', @zeek_{rName}_field_names.zip(event.get('[message]')).to_h)\"",
            f'        }}',
            f'      }}',
            f'    }}',
        ]
        if addFields or tags:
            lines += [
                '',
                f'    mutate {{',
                f'      id => "mutate_add_fields_zeek_{rName}"',
            ]
            if addFields:
                lines += (
                    [f'      add_field => {{']
                    + [f'        "[zeek_cols][{k}]" => "{v}"' for k, v in addFields]
                    + [f'      }}']
                )
            if tags:
                lines += [f'      add_tag => [ {tags} ]']
            lines += [f'    }}']
        lines += [f'  }}']
        print('\n'.join(lines), file=f)
    print('\n}', file=f)

    # time fields (other than ts) need to be converted from epoch seconds in 1400_zeek_convert.conf
    timeFields = [
        f'"[zeek][{r["log"]}][{x["name"]}]"' for r in records for x in LoggedFields(r) if x['type'] == 'time'
    ]
    if timeFields:
        print('', file=f)
        print('# time fields to add to @zeek_time_fields in ./logstash/pipelines/zeek/1400_zeek_convert.conf', file=f)
        print('#   (use the final field names if any of these are renamed during normalization)', file=f)
        for timeField in timeFields:
            print(f'#   {timeField},', file=f)


###################################################################################################
# boilerplate Arkime field definitions and session views, for ./arkime/etc/config.ini
def WriteArkime(records, f):
    print('# for the [custom-fields] section', file=f)
    for record in records:
        rName = record['log']
        group = args.arkimeGroup if args.arkimeGroup else f'zeek_{rName}'
        print(f"# {rName}.log", file=f)
        if args.url:
            print(f"# {args.url}", file=f)
        for field in LoggedFields(record):
            print(
                f"zeek.{rName}.{field['name']}=db:zeek.{rName}.{field['name']};group:{group};kind:{ZEEK_TO_ARKIME_TYPES[field['type']]};viewerOnly:true;friendly:{field['name']};help:{field['name']}",
                file=f,
            )
        print("", file=f)

    print("# for the [custom-views] section", file=f)
    for record in records:
        rName = record['log']
        rFields = ','.join([f"zeek.{rName}.{x['name']}" for x in LoggedFields(record)])
        print(
            f"o_zeek_{rName}=require:zeek.{rName};title:Zeek {rName}.log;fields:{rFields}",
            file=f,
        )


###################################################################################################
# boilerplate OpenSearch index template mappings, for ./dashboards/templates/composable/component/zeek*.json
def WriteIndexTemplate(records, f):
    flatFields = {}
    for record in records:
        for field in LoggedFields(record):
            flatFields[f"zeek.{record['log']}.{field['name']}"] = {"type": ZEEK_TO_INDEX_TEMPLATE_TYPES[field['type']]}
    f.write(
        json.dumps(
            {"template": {"mappings": {"properties": NestProperties(flatFields)}}},
            indent=2,
        )
    )
    f.write('\n')


###################################################################################################
# boilerplate WISE value-action field names, for the allFields array in ./arkime/wise/source.zeeklogs.js
def WriteWise(records, f):
    for fieldName in sorted(set(f"zeek.{r['log']}.{x['name']}" for r in records for x in LoggedFields(r))):
        print(f'      "{fieldName}",', file=f)


###################################################################################################
if __name__ == '__main__':
    main()
