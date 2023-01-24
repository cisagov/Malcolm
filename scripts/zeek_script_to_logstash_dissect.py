#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import io
import json
import logging
import os
import sys
import zeekscript
from slugify import slugify

###################################################################################################
args = None
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()


def IsRecordNode(Node):
    return Node.name() == 'type_decl'


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
                'Do some stuff.',
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
        help="Input value(s)",
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    args.verbose = logging.ERROR - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.debug(os.path.join(script_path, script_name))
    logging.debug("Arguments: {}".format(sys.argv[1:]))
    logging.debug("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    records = []

    for val in args.input if args.input else ():
        logging.info(val)
        contents = None
        with open(val, 'rb') as f:
            contents = f.read()
        script = zeekscript.Script(io.BytesIO(contents))
        if script.parse() and not script.has_error():
            logging.debug(f'Parsed {os.path.basename(val)}')
            for typeDeclNode, _ in script.root.traverse(
                include_cst=False,
                predicate=IsRecordNode,
            ):
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

                if typeName:
                    record = {}
                    record["name"] = typeName
                    record["fields"] = []

                    for typeInfoNode, indent in typeDeclNode.traverse(
                        include_cst=False,
                        predicate=IsLoggedFieldNode,
                    ):
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
                        if fieldName and fieldType:
                            if args.expandId and (fieldType == "conn-id"):
                                record["fields"] = record["fields"] + [
                                    {"name": "orig_h", "type": "addr"},
                                    {"name": "orig_p", "type": "port"},
                                    {"name": "resp_h", "type": "addr"},
                                    {"name": "resp_p", "type": "port"},
                                ]
                            else:
                                record["fields"].append({"name": fieldName, "type": fieldType})

                    if len(record["fields"]) > 0:
                        records.append(record)

        else:
            logging.error(f'Parsing {os.path.basename(val)}: "{script.get_error()}"')

        print(json.dumps({"records": records}, indent=2))


###################################################################################################
if __name__ == '__main__':
    main()
