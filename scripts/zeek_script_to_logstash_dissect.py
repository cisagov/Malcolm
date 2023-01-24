#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This script takes as input the filenames of one or more .zeek scripts which
# contain records (see https://docs.zeek.org/en/master/script-reference/types.html#type-record).
# The scripts are parsed into their constitutent records and &log fields.
# Each record is then printed out in the format used by Malcolm's logstash
# filters for parsing Zeek logs (see
# https://github.com/idaholab/Malcolm/blob/76525caadfc7b0c27d0e7764a388559c18f63903/logstash/pipelines/zeek/11_zeek_logs.conf#L279-L311),
# which can be used to create boilerplate for adding a new Zeek parser to Malcolm
# (see https://idaholab.github.io/Malcolm/docs/contributing-logstash.html#LogstashZeek).
# Pay close attention to the comment in the logstash filter:
#    # zeek's default delimiter is a literal tab, MAKE SURE YOUR EDITOR DOESN'T SCREW IT UP
# If you are copy/pasting this boilerplace, ensure your editor doesn't lose the TAB characters

import argparse
import io
import json
import logging
import os
import sys
import zeekscript
import operator
from slugify import slugify

###################################################################################################
args = None
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

ZEEK_DELIMITER_CHAR = '\t'

# Used as a predicate to filter nodes during tree traversal.
# see https://github.com/zeek/zeekscript/blob/4a3512dd114e2709d6738016176c27a65f3f1492/zeekscript/node.py#L157

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

    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'Parse Zeek .script files and generate boilerplate for a Malcolm Logstash filter for parsing those Zeek logs.',
                'see https://idaholab.github.io/Malcolm/docs/contributing-logstash.html#LogstashZeek',
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

    # parse each .zeek script
    for val in sorted(args.input) if args.input else ():
        logging.info(val)
        contents = None
        with open(val, 'rb') as f:
            contents = f.read()
        script = zeekscript.Script(io.BytesIO(contents))
        if script.parse() and not script.has_error():
            logging.info(f'Parsed {os.path.basename(val)}')

            # find each "record" node
            for typeDeclNode, _ in script.root.traverse(
                include_cst=False,
                predicate=IsRecordNode,
            ):
                # determine the name of the record node
                # this isn't *exactly* going to match the acutal filename
                # of the .log file, but it'll be close enough for a good start
                typeName = None
                try:
                    typeName = slugify(
                        script.get_content(
                            *[
                                n
                                for n, _ in typeDeclNode.traverse(
                                    include_cst=False,
                                )
                                if n.name() == 'id'
                            ][0].script_range()
                        ).decode('utf-8')
                    ).replace('-', '_')
                except (AttributeError, IndexError):
                    pass

                # process the fields belonging to this record
                if typeName:
                    logging.info(f'Found record {typeName}')
                    record = {}
                    record["name"] = typeName
                    record["fields"] = []

                    # find each "logged field" inside this record
                    for typeInfoNode, indent in typeDeclNode.traverse(
                        include_cst=False,
                        predicate=IsLoggedFieldNode,
                    ):
                        # determine the field's name and type
                        fieldName = None
                        fieldType = None
                        try:
                            fieldName = slugify(
                                script.get_content(
                                    *[
                                        n
                                        for n, _ in typeInfoNode.traverse(
                                            include_cst=False,
                                        )
                                        if n.name() == 'id'
                                    ][0].script_range()
                                ).decode('utf-8')
                            ).replace('-', '_')
                            fieldType = slugify(
                                script.get_content(
                                    *[
                                        n
                                        for n, _ in typeInfoNode.traverse(
                                            include_cst=False,
                                        )
                                        if n.name() == 'type'
                                    ][0].script_range()
                                ).decode('utf-8')
                            )
                        except (AttributeError, IndexError):
                            pass

                        # if we found the name and type, add it to the record
                        if fieldName and fieldType:
                            logging.info(f'Found field {typeName}.{fieldName} ({fieldType})')
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

                    # valid record? add it to the final list
                    if len(record["fields"]) > 0:
                        records.append(record)

        else:
            logging.error(f'Parsing {os.path.basename(val)}: "{script.get_error()}"')

        records.sort(key=operator.itemgetter('name'))

        logging.debug(json.dumps({"records": records}, indent=2))

        # output boilerplate Logstash filter for use in Malcolm
        for record in records:
            rName = record['name']
            rFieldsZip = ', '.join(["'" + x['name'] + "'" for x in record['fields']])
            rFieldsDissect = ZEEK_DELIMITER_CHAR.join([f'%{{[zeek_cols][{x["name"]}]}}' for x in record['fields']])
            tags = ', '.join(['"' + x + '"' for x in args.tags])
            print(
                '\n'.join(
                    (
                        f'}} else if ([log_source] == "{rName}") {{',
                        f'  #############################################################################################################################',
                        f'  # {rName}.log',
                        f'  # {args.url}',
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
                )
            )


###################################################################################################
if __name__ == '__main__':
    main()
