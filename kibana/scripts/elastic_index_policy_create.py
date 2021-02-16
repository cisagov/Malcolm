#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import re
import os
import sys
import time

TEMPLATE_POLICY_ID_DEFAULT = 'session_index_policy'
TEMPLATE_SCHEMA_VERSION_DEFAULT = 1
POLICY_STATE_HOT = 'hot'
POLICY_STATE_SNAPSHOT = 'recent'
POLICY_STATE_COLD = 'cold'
POLICY_STATE_CLOSED = 'closed'
POLICY_STATE_DELETE = 'delete'
POLICY_STATE_HOT_REPLICAS = 0
POLICY_SNAPSHOT_NAME = 'session_snapshot'

###################################################################################################
debug = False
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()

###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
  if v.lower() in ('yes', 'true', 't', 'y', '1'):
    return True
  elif v.lower() in ('no', 'false', 'f', 'n', '0'):
    return False
  else:
    raise argparse.ArgumentTypeError('Boolean value expected.')

###################################################################################################
# main
def main():
  global debug

  parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
  parser.add_argument('-v', '--verbose', dest='debug', type=str2bool, nargs='?', const=True, default=False, help="Verbose output")
  parser.add_argument('--policy', dest='policyId', metavar='<str>', type=str, default=TEMPLATE_POLICY_ID_DEFAULT, help='Index management policy ID')
  parser.add_argument('--version', dest='schemaVersion', metavar='<int>', type=int, default=TEMPLATE_SCHEMA_VERSION_DEFAULT, help='Index management policy template schema version')
  parser.add_argument('--replicas', dest='hotReplicaCount', metavar='<int>', type=int, default=POLICY_STATE_HOT_REPLICAS, help='Replica count for hot state')
  parser.add_argument('--snapshot', dest='snapshotAge', metavar='<str>', type=str, default='1d', help='Snapshot index age (e.g., 1d); 0 to disable')
  parser.add_argument('--snapshot-repo', dest='snapshotRepo', metavar='<str>', type=str, default=os.getenv('ISM_SNAPSHOT_REPO', 'logs'), help='Snapshot repository')
  parser.add_argument('--snapshot-name', dest='snapshotName', metavar='<str>', type=str, default=POLICY_SNAPSHOT_NAME, help='Snapshot name')
  parser.add_argument('--cold', dest='coldAge', metavar='<str>', type=str, default='30d', help='Cold state index age (e.g., 30d); 0 to disable')
  parser.add_argument('--close', dest='closeAge', metavar='<str>', type=str, default='60d', help='Close state index age (e.g., 60d); 0 to disable')
  parser.add_argument('--delete', dest='deleteAge', metavar='<str>', type=str, default='365d', help='Delete state index age (e.g., 365d); 0 to disable')

  try:
    parser.error = parser.exit
    args = parser.parse_args()
  except SystemExit:
    parser.print_help()
    exit(2)

  debug = args.debug
  if debug:
    eprint(os.path.join(scriptPath, scriptName))
    eprint("Arguments: {}".format(sys.argv[1:]))
    eprint("Arguments: {}".format(args))
  else:
    sys.tracebacklimit = 0

  # verify that age parameters are in the right format (number and units)
  for ageParam in (args.snapshotAge, args.coldAge, args.closeAge, args.deleteAge):
    if not ((ageParam == '0') or re.match(r'^\d+[dhms]$', ageParam)):
      raise argparse.ArgumentTypeError(f'Invalid age parameter {ageParam}')

  # store policy information
  policyDict = dict()
  policyDict['policy_id'] = args.policyId
  policyDict['description'] = f'Index state management policy to snapshot indices after {args.snapshotAge}, move them into a cold state after {args.coldAge} and delete them after {args.deleteAge}'
  policyDict['last_updated_time'] = time.time_ns() // 1000000
  policyDict['schema_version'] = args.schemaVersion
  policyDict['error_notification'] = None

  # list of states and their transitions
  states = list()

  # hot -> snapshot -> cold -> closed -> deleted

  # hot state is default and always exists
  policyDict['default_state'] = POLICY_STATE_HOT
  hotState = dict()
  hotState['name'] = POLICY_STATE_HOT
  hotState['actions'] = [{ 'replica_count' : { 'number_of_replicas' : args.hotReplicaCount}}]
  states.append(hotState)

  # create a "snapshot" state for backup and set the previous state's transition to it
  if (args.snapshotAge != '0'):
    snapshotState = dict()
    snapshotState['name'] = POLICY_STATE_SNAPSHOT
    snapshotState['actions'] = [{ 'snapshot' : { 'repository' : args.snapshotRepo, 'snapshot' : args.snapshotName}}]
    states[len(states)-1]['transitions'] = [{'state_name' : POLICY_STATE_SNAPSHOT,
                                             'conditions' : { 'min_index_age' : args.snapshotAge}}]
    states.append(snapshotState)

  # create a "cold" state for read-only indices and set the previous state's transition to it
  if (args.coldAge != '0'):
    coldState = dict()
    coldState['name'] = POLICY_STATE_COLD
    coldState['actions'] = [{ 'read_only' : {}}]
    states[len(states)-1]['transitions'] = [{'state_name' : POLICY_STATE_COLD,
                                             'conditions' : { 'min_index_age' : args.coldAge}}]
    states.append(coldState)

  # create a "closed" state for closed indices and set the previous state's transition to it
  if (args.closeAge != '0'):
    closedState = dict()
    closedState['name'] = POLICY_STATE_CLOSED
    closedState['actions'] = [{ 'close' : {}}]
    states[len(states)-1]['transitions'] = [{'state_name' : POLICY_STATE_CLOSED,
                                             'conditions' : { 'min_index_age' : args.closeAge}}]
    states.append(closedState)

  # create a "deleted" state for deleted indices and set the previous state's transition to it
  if (args.deleteAge != '0'):
    deleteState = dict()
    deleteState['name'] = POLICY_STATE_DELETE
    deleteState['actions'] = [{ 'delete' : {}}]
    states[len(states)-1]['transitions'] = [{'state_name' : POLICY_STATE_DELETE,
                                             'conditions' : { 'min_index_age' : args.deleteAge}}]
    states.append(deleteState)

  # the final state doesn't transition
  states[len(states)-1]['transitions'] = []

  policyDict['states'] = states
  policy = dict()
  policy['policy'] = policyDict
  print(json.dumps(policy))

if __name__ == '__main__':
  main()
