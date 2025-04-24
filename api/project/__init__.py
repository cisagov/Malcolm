import dateparser
import json
import malcolm_utils
import os
import platform
import psutil
import random
import re
import requests
import string
import traceback
import urllib3
import warnings

from collections import defaultdict, OrderedDict
from collections.abc import Iterable
from datetime import datetime, timezone
from flask import Flask, jsonify, request
from requests.auth import HTTPBasicAuth
from urllib.parse import urlparse, urljoin

# map categories of field names to OpenSearch dashboards
fields_to_urls = []
fields_to_urls.append(
    [
        r'^(event\.(risk|severity)\w*|(rule|vulnerability|threat)\.*)$',
        ['DASH:d2dd0180-06b1-11ec-8c6b-353266ade330', 'DASH:95479950-41f2-11ea-88fa-7151df485405'],
    ]
)
fields_to_urls.append([r'^related\.(user|password)$', ['DASH:95479950-41f2-11ea-88fa-7151df485405']])
fields_to_urls.append([r'^event\.(action|result)$', ['DASH:a33e0a50-afcd-11ea-993f-b7d8522a8bed']])
fields_to_urls.append([r'^event\.(dataset|provider)$', ['DASH:0ad3d7c2-3441-485e-9dfe-dbb22e84e576']])
fields_to_urls.append(
    [
        r'^(zeek\.conn\.|(source|destination|related).(oui|ip|port|mac|geo)|network\.(community_id|transport|protocol\w*))$',
        ['DASH:abdd7550-2c7c-40dc-947e-f6d186a158c4'],
    ]
)
fields_to_urls.append([r'^(suricata|rule)\.', ['DASH:5694ca60-cbdf-11ec-a50a-5fedd672f5c5']])
fields_to_urls.append(
    [r'^zeek\.bacnet.*\.', ['DASH:2bec1490-eb94-11e9-a384-0fcf32210194', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append(
    [r'^zeek\.bestguess\.', ['DASH:12e3a130-d83b-11eb-a0b0-f328ce09b0b7', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append(
    [r'^zeek\.bsap.*\.', ['DASH:ca5799a0-56b5-11eb-b749-576de068f8ad', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append([r'^zeek\.dce_rpc\.', ['DASH:432af556-c5c0-4cc3-8166-b274b4e3a406']])
fields_to_urls.append([r'^zeek\.dhcp\.', ['DASH:2d98bb8e-214c-4374-837b-20e1bcd63a5e']])
fields_to_urls.append(
    [r'^zeek\.dnp3.*\.', ['DASH:870a5862-6c26-4a08-99fd-0c06cda85ba3', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append(
    [r'^((source|destination)\.ip_reverse_dns|(zeek\.)?dns\.)', ['DASH:2cf94cd0-ecab-40a5-95a7-8419f3a39cd9']]
)
fields_to_urls.append(
    [r'^zeek\.ecat.*\.', ['DASH:4a073440-b286-11eb-a4d4-09fa12a6ebd4', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append(
    [r'^zeek\.(cip|enip)\.', ['DASH:29a1b290-eb98-11e9-a384-0fcf32210194', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append([r'^(related\.hash|(zeek\.)?files\.)', ['DASH:9ee51f94-3316-4fc5-bd89-93a52af69714']])
fields_to_urls.append([r'^zeek\.ftp\.', ['DASH:078b9aa5-9bd4-4f02-ae5e-cf80fa6f887b']])
fields_to_urls.append(
    [r'^zeek\.genisys.*\.', ['DASH:03207c00-d07e-11ec-b4a7-d1b4003706b7', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append(
    [r'^zeek\.ge_srtp.*\.', ['DASH:e233a570-45d9-11ef-96a6-432365601033', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append([r'^zeek\.gquic\.', ['DASH:11ddd980-e388-11e9-b568-cf17de8e860c']])
fields_to_urls.append(
    [r'^zeek\.hart_ip.*\.', ['DASH:3a9e3440-75e2-11ef-8138-03748f839a49', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append([r'^zeek\.http\.', ['DASH:37041ee1-79c0-4684-a436-3173b0e89876']])
fields_to_urls.append([r'^zeek\.intel\.', ['DASH:36ed695f-edcc-47c1-b0ec-50d20c93ce0f']])
fields_to_urls.append([r'^zeek\.irc\.', ['DASH:76f2f912-80da-44cd-ab66-6a73c8344cc3']])
fields_to_urls.append([r'^zeek\.kerberos\.', ['DASH:82da3101-2a9c-4ae2-bb61-d447a3fbe673']])
fields_to_urls.append([r'^zeek\.ldap.*\.', ['DASH:05e3e000-f118-11e9-acda-83a8e29e1a24']])
fields_to_urls.append([r'^zeek\.login\.', ['DASH:c2549e10-7f2e-11ea-9f8a-1fe1327e2cd2']])
fields_to_urls.append(
    [
        r'^zeek\.(known_modbus|modbus).*\.',
        ['DASH:152f29dc-51a2-4f53-93e9-6e92765567b8', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf'],
    ]
)
fields_to_urls.append([r'^zeek\.mqtt.*\.', ['DASH:87a32f90-ef58-11e9-974e-9d600036d105']])
fields_to_urls.append([r'^zeek\.mysql\.', ['DASH:50ced171-1b10-4c3f-8b67-2db9635661a6']])
fields_to_urls.append(
    [r'^zeek\.notice\.', ['DASH:f1f09567-fc7f-450b-a341-19d2f2bb468b', 'DASH:95479950-41f2-11ea-88fa-7151df485405']]
)
fields_to_urls.append([r'^zeek\.ntlm\.', ['DASH:543118a9-02d7-43fe-b669-b8652177fc37']])
fields_to_urls.append([r'^zeek\.ntp\.', ['DASH:af5df620-eeb6-11e9-bdef-65a192b7f586']])
fields_to_urls.append(
    [r'^zeek\.opcua.*\.', ['DASH:dd87edd0-796a-11ec-9ce6-b395c1ff58f4', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append([r'^zeek\.ospf\.', ['DASH:1cc01ff0-5205-11ec-a62c-7bc80e88f3f0']])
fields_to_urls.append([r'^zeek\.pe\.', ['DASH:0a490422-0ce9-44bf-9a2d-19329ddde8c3']])
fields_to_urls.append(
    [r'^zeek\.profinet.*\.', ['DASH:a7514350-eba6-11e9-a384-0fcf32210194', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf']]
)
fields_to_urls.append([r'^zeek\.radius\.', ['DASH:ae79b7d1-4281-4095-b2f6-fa7eafda9970']])
fields_to_urls.append([r'^zeek\.rdp\.', ['DASH:7f41913f-cba8-43f5-82a8-241b7ead03e0']])
fields_to_urls.append([r'^zeek\.rfb\.', ['DASH:f77bf097-18a8-465c-b634-eb2acc7a4f26']])
fields_to_urls.append(
    [
        r'^zeek\.(s7comm.*|(iso_)?cotp)\.',
        ['DASH:e76d05c0-eb9f-11e9-a384-0fcf32210194', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf'],
    ]
)
fields_to_urls.append(
    [
        r'^(zeek\.signatures|rule)\.',
        [
            'DASH:665d1610-523d-11e9-a30e-e3576242f3ed',
            'DASH:95479950-41f2-11ea-88fa-7151df485405',
            'DASH:f1f09567-fc7f-450b-a341-19d2f2bb468b',
        ],
    ]
)
fields_to_urls.append([r'^zeek\.sip\.', ['DASH:0b2354ae-0fe9-4fd9-b156-1c3870e5c7aa']])
fields_to_urls.append([r'^zeek\.smb.*\.', ['DASH:42e831b9-41a9-4f35-8b7d-e1566d368773']])
fields_to_urls.append([r'^zeek\.smtp\.', ['DASH:bb827f8e-639e-468c-93c8-9f5bc132eb8f']])
fields_to_urls.append([r'^zeek\.snmp\.', ['DASH:4e5f106e-c60a-4226-8f64-d534abb912ab']])
fields_to_urls.append([r'^zeek\.software\.', ['DASH:87d990cc-9e0b-41e5-b8fe-b10ae1da0c85']])
fields_to_urls.append([r'^zeek\.ssh\.', ['DASH:caef3ade-d289-4d05-a511-149f3e97f238']])
fields_to_urls.append([r'^zeek\.stun.*\.', ['DASH:fa477130-2b8a-11ec-a9f2-3911c8571bfd']])
fields_to_urls.append(
    [
        r'^zeek\.synchrophasor.*\.',
        ['DASH:2cc56240-e460-11ed-a9d5-9f591c284cb4', 'DASH:4a4bde20-4760-11ea-949c-bbb5a9feecbf'],
    ]
)
fields_to_urls.append([r'^zeek\.syslog\.', ['DASH:92985909-dc29-4533-9e80-d3182a0ecf1d']])
fields_to_urls.append([r'^zeek\.tds\.', ['DASH:bed185a0-ef82-11e9-b38a-2db3ee640e88']])
fields_to_urls.append([r'^zeek\.tds_rpc\.', ['DASH:32587740-ef88-11e9-b38a-2db3ee640e88']])
fields_to_urls.append([r'^zeek\.tds_sql_batch\.', ['DASH:fa141950-ef89-11e9-b38a-2db3ee640e88']])
fields_to_urls.append([r'^zeek\.tftp\.', ['DASH:bf5efbb0-60f1-11eb-9d60-dbf0411cfc48']])
fields_to_urls.append([r'^zeek\.tunnel\.', ['DASH:11be6381-beef-40a7-bdce-88c5398392fc']])
fields_to_urls.append([r'^zeek\.weird\.', ['DASH:1fff49f6-0199-4a0f-820b-721aff9ff1f1']])
fields_to_urls.append(
    [
        r'^zeek\.(ssl|ocsp|known_certs|x509)\.',
        ['DASH:7f77b58a-df3e-4cc2-b782-fd7f8bad8ffb', 'DASH:024062a6-48d6-498f-a91a-3bf2da3a3cd3'],
    ]
)

# field type maps from our various field sources
field_type_map = defaultdict(lambda: 'string')
field_type_map['date'] = 'date'
field_type_map['datetime'] = 'date'
field_type_map['double'] = 'float'
field_type_map['float'] = 'float'
field_type_map['geo_point'] = 'geo'
field_type_map['integer'] = 'integer'
field_type_map['ip'] = 'ip'
field_type_map['long'] = 'integer'
field_type_map['time'] = 'date'
field_type_map['timestamp'] = 'date'

# field type maps to various supported "missing" values
# TODO: do I need to handle weird ones like "date" and "geo"?
missing_field_map = defaultdict(lambda: '-')
missing_field_map['double'] = 0.0
missing_field_map['float'] = 0.0
missing_field_map['integer'] = 0
missing_field_map['ip'] = '0.0.0.0'
missing_field_map['long'] = 0

urllib3.disable_warnings()
warnings.filterwarnings(
    "ignore",
    message="The localize method is no longer necessary, as this time zone supports the fold attribute",
)

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config.from_object("project.config.Config")

debugApi = app.config["MALCOLM_API_DEBUG"] == "true"

arkimeSsl = malcolm_utils.str2bool(app.config["ARKIME_SSL"])
arkimeHost = app.config["ARKIME_HOST"]
arkimePort = app.config["ARKIME_PORT"]
arkimeStatusUrl = f'http{"s" if arkimeSsl else ""}://{arkimeHost}:{arkimePort}/_ns_/nstest.html'
dashboardsUrl = app.config["DASHBOARDS_URL"]
dashboardsHelperHost = app.config["DASHBOARDS_HELPER_HOST"]
dashboardsMapsPort = app.config["DASHBOARDS_MAPS_PORT"]
databaseMode = malcolm_utils.DatabaseModeStrToEnum(app.config["OPENSEARCH_PRIMARY"])
filebeatHost = app.config["FILEBEAT_HOST"]
filebeatTcpJsonPort = app.config["FILEBEAT_TCP_JSON_PORT"]
freqUrl = app.config["FREQ_URL"]
logstashApiPort = app.config["LOGSTASH_API_PORT"]
logstashHost = app.config["LOGSTASH_HOST"]
logstashLJPort = app.config["LOGSTASH_LJ_PORT"]
logstashMapsPort = app.config["LOGSTASH_LJ_PORT"]
logstashUrl = f'http://{logstashHost}:{logstashApiPort}'
netboxUrl = malcolm_utils.remove_suffix(malcolm_utils.remove_suffix(app.config["NETBOX_URL"], '/'), '/api')
netboxToken = app.config["NETBOX_TOKEN"]
opensearchUrl = app.config["OPENSEARCH_URL"]
pcapMonitorHost = app.config["PCAP_MONITOR_HOST"]
pcapTopicPort = app.config["PCAP_TOPIC_PORT"]
zeekExtractedFileLoggerHost = app.config["ZEEK_EXTRACTED_FILE_LOGGER_HOST"]
zeekExtractedFileLoggerTopicPort = app.config["ZEEK_EXTRACTED_FILE_LOGGER_TOPIC_PORT"]
zeekExtractedFileMonitorHost = app.config["ZEEK_EXTRACTED_FILE_MONITOR_HOST"]
zeekExtractedFileTopicPort = app.config["ZEEK_EXTRACTED_FILE_TOPIC_PORT"]

opensearchLocal = (databaseMode == malcolm_utils.DatabaseMode.OpenSearchLocal) or (
    opensearchUrl == 'http://opensearch:9200'
)
opensearchSslVerify = app.config["OPENSEARCH_SSL_CERTIFICATE_VERIFICATION"] == "true"
opensearchCreds = (
    malcolm_utils.ParseCurlFile(app.config["OPENSEARCH_CREDS_CONFIG_FILE"])
    if (not opensearchLocal)
    else defaultdict(lambda: None)
)

DatabaseInitArgs = {}
if urlparse(opensearchUrl).scheme == 'https':
    DatabaseInitArgs['verify_certs'] = opensearchSslVerify
    DatabaseInitArgs['ssl_assert_hostname'] = False
    DatabaseInitArgs['ssl_show_warn'] = False

if opensearchCreds['user'] is not None:
    opensearchHttpAuth = (opensearchCreds['user'], opensearchCreds['password'])
    opensearchReqHttpAuth = HTTPBasicAuth(opensearchCreds['user'], opensearchCreds['password'])
else:
    opensearchHttpAuth = None
    opensearchReqHttpAuth = None

if databaseMode == malcolm_utils.DatabaseMode.ElasticsearchRemote:
    import elasticsearch as DatabaseImport
    from elasticsearch_dsl import Search as SearchClass, A as AggregationClass, Q as QueryClass

    DatabaseClass = DatabaseImport.Elasticsearch
    if opensearchHttpAuth:
        DatabaseInitArgs['basic_auth'] = opensearchHttpAuth
else:
    import opensearchpy as DatabaseImport
    from opensearchpy import Search as SearchClass, A as AggregationClass, Q as QueryClass

    DatabaseClass = DatabaseImport.OpenSearch
    if opensearchHttpAuth:
        DatabaseInitArgs['http_auth'] = opensearchHttpAuth

databaseClient = DatabaseClass(
    hosts=[opensearchUrl],
    **DatabaseInitArgs,
)


def doctype_is_host_logs(d):
    return any([str(d).lower().startswith(x) for x in ['host', 'beat', 'miscbeat']])


def random_id(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def get_request_arguments(req):
    arguments = {}
    if 'POST' in malcolm_utils.get_iterable(req.method):
        if (data := req.get_json() if req.is_json else None) and isinstance(data, dict):
            arguments.update(data)
    if 'GET' in malcolm_utils.get_iterable(req.method):
        arguments.update(request.args)
    if debugApi:
        print(f"{req.method} {req.path} arguments: {json.dumps(arguments)}")
    return arguments


def gettimes(args):
    """Parses 'from' and 'to' times out of the provided dictionary, returning
    two datetime objects

    Parameters
    ----------
    args : dict
        The dictionary which should contain 'from' and 'to' times. Missing
        times are returned as None.
        Time can be UNIX time integers represented as strings or strings
        of various formats, in which case a "best guess" conversion is done.
        If no time zone information is provided, UTC is assumed.

    Returns
    -------
    return start_time, end_time
        datetime objects representing the start and end time for a query
    """
    if start_time_str := args.get("from"):
        start_time = (
            datetime.utcfromtimestamp(int(start_time_str))
            if start_time_str.isdigit()
            else dateparser.parse(start_time_str)
        )
    else:
        start_time = None
    if end_time_str := args.get("to"):
        end_time = (
            datetime.utcfromtimestamp(int(end_time_str)) if end_time_str.isdigit() else dateparser.parse(end_time_str)
        )
    else:
        end_time = None

    return start_time, end_time


def getfilters(args):
    """Parses 'filter' dictionary from the request args dictionary, returning
    the filters themselves as a dict()

    e.g.,

    https://localhost/mapi/agg?from=25 years ago&to=now&filter={"network.direction":"outbound"}

    Parameters
    ----------
    args : dict
        The dictionary which should contain 'filter'.

    Returns
    -------
    return filters
        dict containing the filters, e.g., { "fieldname1": "value", "fieldname2": 1234, "fieldname3": ["abc", "123"] }
    """
    try:
        if filters := args.get("filter"):
            if isinstance(filters, str):
                filters = json.loads(filters)
            if isinstance(filters, dict):
                return filters
            else:
                return None
        else:
            return None
    except ValueError as ve:
        if debugApi:
            print(f"Error {type(ve).__name__}: {str(ve)} for {type(filters).__name__} filter: {filters})")
        return None


def urls_for_field(fieldname, start_time=None, end_time=None):
    """looks up a list of URLs relevant to a particular database field

    Parameters
    ----------
    fieldname : string
        the name of the field to be mapped to URLs
    start_time : datetime
        the start time for the query
    end_time : datetime
        the end time for the query

    Returns
    -------
    return translated
        a list of URLs relevant to the field
    """
    start_time_str = (
        f"'{start_time.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')}'"
        if start_time is not None
        else 'now-1d'
    )
    end_time_str = (
        f"'{end_time.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')}'" if end_time is not None else 'now'
    )
    translated = []

    if databaseMode != malcolm_utils.DatabaseMode.ElasticsearchRemote:
        for field in malcolm_utils.get_iterable(fieldname):
            for url_regex_pair in fields_to_urls:
                if (len(url_regex_pair) == 2) and re.search(url_regex_pair[0], field, flags=re.IGNORECASE):
                    for url in url_regex_pair[1]:
                        if url.startswith('DASH:'):
                            translated.append(
                                f"/dashboards/app/dashboards#/view/{url[5:]}?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:{start_time_str},to:{end_time_str}))"
                            )
                        else:
                            translated.append(url)

    return list(set(translated))


def doctype_from_args(args):
    """returns the value of the doctype field in the args dictionary

    Parameters
    ----------
    args : dict
        The dictionary which should contain 'doctype' value. Missing
        key returns value of app.config["DOCTYPE_DEFAULT"]

    Returns
    -------
    return doctype
        network|host
    """
    return str(malcolm_utils.deep_get(args, ["doctype"], app.config["DOCTYPE_DEFAULT"])).lower()


def index_from_args(args):
    """returns the appropriate index for searching the document type
    in the args dictionary

    Parameters
    ----------
    args : dict
        The dictionary which should contain 'doctype' value. Missing
        key returns value of app.config["MALCOLM_NETWORK_INDEX_PATTERN"]

    Returns
    -------
    return index
        app.config["MALCOLM_OTHER_INDEX_PATTERN"],
        app.config["ARKIME_NETWORK_INDEX_PATTERN"],
        app.config["MALCOLM_NETWORK_INDEX_PATTERN"],
    """
    index = None
    if dtype := doctype_from_args(args):
        if doctype_is_host_logs(dtype):
            index = app.config["MALCOLM_OTHER_INDEX_PATTERN"]
        elif dtype.startswith('arkime') or dtype.startswith('session'):
            index = app.config["ARKIME_NETWORK_INDEX_PATTERN"]
        else:
            index = app.config["MALCOLM_NETWORK_INDEX_PATTERN"]
    return index


def timefield_from_args(args):
    """returns the appropriate time field for searching the document type
    in the args dictionary

    Parameters
    ----------
    args : dict
        The dictionary which should contain 'doctype' value. Missing
        key returns value of app.config["MALCOLM_NETWORK_INDEX_PATTERN"]

    Returns
    -------
    timefield index
        app.config["MALCOLM_OTHER_INDEX_TIME_FIELD"],
        app.config["ARKIME_NETWORK_INDEX_TIME_FIELD"],
        app.config["MALCOLM_NETWORK_INDEX_TIME_FIELD"],
    """
    timefield = None
    if dtype := doctype_from_args(args):
        if doctype_is_host_logs(dtype):
            timefield = app.config["MALCOLM_OTHER_INDEX_TIME_FIELD"]
        elif dtype.startswith('arkime') or dtype.startswith('session'):
            timefield = app.config["ARKIME_NETWORK_INDEX_TIME_FIELD"]
        else:
            timefield = app.config["MALCOLM_NETWORK_INDEX_TIME_FIELD"]
    return timefield


def filtertime(search, args, default_from="1 day ago", default_to="now"):
    """Applies a time filter (inclusive; extracted from request arguments) to an OpenSearch query and
    returns the range as a tuple of integers representing the milliseconds since EPOCH. If
    either end of the range is unspecified, the start and end times default to "1 day ago" and "now",
    respectively.

    Parameters
    ----------
    search : opensearchpy.Search
        The object representing the OpenSearch Search query
    args : dict
        The dictionary which should contain 'from' and 'to' times (see gettimes) and 'doctype'

    Returns
    -------
    start_time,
    end_time,
        integers representing the start and end times for the query, in milliseconds since the epoch
    search.filter(...)
        filtered search object
    """
    start_time, end_time = gettimes(args)
    start_time_ms = int(
        start_time.timestamp() * 1000 if start_time is not None else dateparser.parse(default_from).timestamp() * 1000
    )
    end_time_ms = int(
        end_time.timestamp() * 1000 if end_time is not None else dateparser.parse(default_to).timestamp() * 1000
    )
    return (
        start_time_ms,
        end_time_ms,
        (
            search.filter(
                "range",
                **{
                    timefield_from_args(args): {
                        "gte": start_time_ms,
                        "lte": end_time_ms,
                        "format": "epoch_millis",
                    }
                },
            )
            if search
            else None
        ),
    )


def filtervalues(search, args):
    """Applies field value filters (logically AND-ing them) to an OpenSearch query. Using a !
    effectively negates/excludes the filter. Using a 'null' value implies "does not exist."

    Parameters
    ----------
    search : opensearchpy.Search
        The object representing the OpenSearch Search query
    args : dict
        The dictionary which should contain 'filter' (see getfilters)

    Returns
    -------
    filters
        dict containing the filters, e.g., { "fieldname1": "value", "fieldname2": 1234, "fieldname3": ["abc", "123"] }
    search.filter(...)
        filtered search object
    """
    if (s := search) and (filters := getfilters(args)) and isinstance(filters, dict):
        # loop over filters, AND'ing all of them
        for fieldname, filtervalue in filters.items():
            if fieldname.startswith('!'):
                # AND NOT filter
                if filtervalue is not None:
                    # field != value
                    s = s.exclude(
                        "terms",
                        **{fieldname[1:]: malcolm_utils.get_iterable(filtervalue)},
                    )
                else:
                    # field exists ("is not null")
                    s = s.filter("exists", field=fieldname[1:])
            else:
                # AND filter
                if filtervalue is not None:
                    # field == value
                    s = s.filter(
                        "terms",
                        **{fieldname: malcolm_utils.get_iterable(filtervalue)},
                    )
                else:
                    # field does not exist ("is null")
                    s = s.filter('bool', must_not=DatabaseImport.helpers.query.Q('exists', field=fieldname))

    if debugApi:
        print(f'filtervalues: {json.dumps(s.to_dict())}')
    return (filters, s)


def aggfields(fieldnames, current_request, urls=None):
    """Returns a bucket aggregation for a particular field over a given time range

    Parameters
    ----------
    fieldname : string or Array of string
        The name of the field(s) on which to perform the aggregation
    current_request : Request
        The flask Request object being processed (see gettimes/filtertime and getfilters/filtervalues)
        Uses 'from', 'to', 'limit', 'filter', and 'doctype' from current_request arguments

    Returns
    -------
    values
        list of dicts containing key and doc_count for each bucket
    range
        start_time (seconds since EPOCH) and end_time (seconds since EPOCH) of query
    filter
        dict containing the filters, e.g., { "fieldname1": "value", "fieldname2": 1234, "fieldname3": ["abc", "123"] }
    fields
        the name of the field(s) on which the aggregation was performed
    """
    args = get_request_arguments(current_request)
    idx = index_from_args(args)
    s = SearchClass(
        using=databaseClient,
        index=idx,
    ).extra(size=0)
    start_time_ms, end_time_ms, s = filtertime(s, args)
    filters, s = filtervalues(s, args)
    bucket_limit = int(malcolm_utils.deep_get(args, ["limit"], app.config["RESULT_SET_LIMIT"]))
    last_bucket = s.aggs

    for fname in malcolm_utils.get_iterable(fieldnames):
        # Get the field mapping type for this field, and map it to a good default "missing"
        #   (empty bucket) label for the bucket missing= parameter below
        mapping = databaseClient.indices.get_field_mapping(
            fields=fname,
            index=idx,
        )
        missing_val = (
            missing_field_map[
                next(
                    iter(
                        malcolm_utils.dictsearch(
                            mapping[next(iter(OrderedDict(sorted(mapping.items(), reverse=True))))], 'type'
                        )
                    ),
                    None,
                )
            ]
            if (mapping and isinstance(mapping, dict))
            else missing_field_map[None]
        )

        # chain on the aggregation for the next field
        last_bucket = last_bucket.bucket(
            fname,
            "terms",
            field=fname,
            size=bucket_limit,
            missing=missing_val,
        )

    response = s.execute()

    top_bucket_name = next(iter(malcolm_utils.get_iterable(fieldnames)))
    result_dict = {
        top_bucket_name: response.aggregations.to_dict().get(top_bucket_name, {}),
        'range': (start_time_ms // 1000, end_time_ms // 1000),
        'filter': filters,
        'fields': malcolm_utils.get_iterable(fieldnames),
    }
    if (urls is not None) and (len(urls) > 0):
        result_dict['urls'] = urls

    return jsonify(result_dict)


@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/agg",
    defaults={'fieldname': 'event.provider'},
    methods=['GET', 'POST'],
)
@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/agg/<fieldname>",
    methods=['GET', 'POST'],
)
def aggregate(fieldname):
    """Returns the aggregated values and counts for a given field name, see aggfields

    Parameters
    ----------
    fieldname : string
        the name of the field(s) to be bucketed (comma-separated if multiple fields)
    request : Request
        see aggfields

    Returns
    -------
    values
        list of dicts containing key and doc_count for each bucket
    range
        start_time (seconds since EPOCH) and end_time (seconds since EPOCH) of query
    """
    start_time, end_time = gettimes(get_request_arguments(request))
    fields = fieldname.split(",")
    return aggfields(
        fields,
        request,
        urls=urls_for_field(fields, start_time=start_time, end_time=end_time),
    )


@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/document",
    methods=['GET', 'POST'],
)
def document():
    """Returns the matching document(s) from the specified index

    Parameters
    ----------
    request : Request
        Uses 'from', 'to', 'limit', 'filter', and 'doctype' from request arguments

    Returns
    -------
    filter
        dict containing the filters, e.g., {"_id":"210301-Cgnjsc2Tkdl38g25D6-cotp-5485"}
    results
        array of the documents retrieved (up to 'limit')
    """
    args = get_request_arguments(request)
    s = SearchClass(
        using=databaseClient,
        index=index_from_args(args),
    ).extra(size=int(malcolm_utils.deep_get(args, ["limit"], app.config["RESULT_SET_LIMIT"])))
    start_time_ms, end_time_ms, s = filtertime(s, args, default_from="1970-1-1", default_to="now")
    filters, s = filtervalues(s, args)
    return jsonify(
        results=s.execute().to_dict().get('hits', {}).get('hits', []),
        range=(start_time_ms // 1000, end_time_ms // 1000),
        filter=filters,
    )


@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/index", methods=['GET']
)
@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/indexes", methods=['GET']
)
@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/indices", methods=['GET']
)
def indices():
    """Provide a list of indices in the OpenSearch data store

    Parameters
    ----------

    Returns
    -------
    indices
        A dict where "indices" contains the array from output of _cat/indices?format=json from the OpenSearch API,
        and malcolm_network_index_pattern, malcolm_other_index_pattern, and arkime_network_index_pattern contain
        their respective index pattern names
    """
    result = {}
    result["indices"] = requests.get(
        f'{opensearchUrl}/_cat/indices?format=json',
        auth=opensearchReqHttpAuth,
        verify=opensearchSslVerify,
    ).json()
    result["malcolm_network_index_pattern"] = app.config["MALCOLM_NETWORK_INDEX_PATTERN"]
    result["malcolm_other_index_pattern"] = app.config["MALCOLM_OTHER_INDEX_PATTERN"]
    result["arkime_network_index_pattern"] = app.config["ARKIME_NETWORK_INDEX_PATTERN"]

    return jsonify(result)


@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/fields",
    methods=['GET', 'POST'],
)
def fields():
    """Provide a list of fields Malcolm "knows about" merged from Arkime's field table, Malcolm's
    OpenSearch template for the sessions indices, and Kibana's field list

    Parameters
    ----------
    request : Request
        template - template name (default is app.config["MALCOLM_TEMPLATE"])
        doctype - network|host
    Returns
    -------
    fields
        A dict of dicts where key is the field name and value may contain 'description' and 'type'
    """
    args = get_request_arguments(request)

    templateName = malcolm_utils.deep_get(args, ["template"], app.config["MALCOLM_TEMPLATE"])
    arkimeFields = (templateName == app.config["MALCOLM_TEMPLATE"]) and (doctype_from_args(args) == 'network')

    fields = defaultdict(dict)

    if arkimeFields:
        try:
            # get fields from Arkime's fields table
            s = SearchClass(
                using=databaseClient,
                index=index_from_args(args),
            ).extra(size=6000)
            for hit in [x['_source'] for x in s.execute().to_dict().get('hits', {}).get('hits', [])]:
                if (fieldname := malcolm_utils.deep_get(hit, ['dbField2'])) and (fieldname not in fields):
                    if debugApi:
                        hit['source'] = 'arkime'
                    fields[fieldname] = {
                        'description': malcolm_utils.deep_get(hit, ['help']),
                        'type': field_type_map[malcolm_utils.deep_get(hit, ['type'])],
                    }
                    if debugApi:
                        fields[fieldname]['original'] = [hit]
        except Exception as e:
            if debugApi:
                print(f"{type(e).__name__}: {str(e)} getting Arkime fields")

    # get fields from OpenSearch template (and descendant components)
    try:
        getTemplateResponseJson = requests.get(
            f'{opensearchUrl}/_index_template/{templateName}',
            auth=opensearchReqHttpAuth,
            verify=opensearchSslVerify,
        ).json()

        for template in malcolm_utils.deep_get(getTemplateResponseJson, ["index_templates"]):
            # top-level fields
            for fieldname, fieldinfo in malcolm_utils.deep_get(
                template,
                ["index_template", "template", "mappings", "properties"],
                {},
            ).items():
                if debugApi:
                    fieldinfo['source'] = f'opensearch.{templateName}'
                if 'type' in fieldinfo:
                    fields[fieldname]['type'] = field_type_map[malcolm_utils.deep_get(fieldinfo, ['type'])]
                if debugApi:
                    fields[fieldname]['original'] = fields[fieldname].get('original', []) + [fieldinfo]

            # descendant component fields
            for componentName in malcolm_utils.get_iterable(
                malcolm_utils.deep_get(template, ["index_template", "composed_of"])
            ):
                getComponentResponseJson = requests.get(
                    f'{opensearchUrl}/_component_template/{componentName}',
                    auth=opensearchReqHttpAuth,
                    verify=opensearchSslVerify,
                ).json()
                for component in malcolm_utils.get_iterable(
                    malcolm_utils.deep_get(getComponentResponseJson, ["component_templates"])
                ):
                    for fieldname, fieldinfo in malcolm_utils.deep_get(
                        component,
                        ["component_template", "template", "mappings", "properties"],
                        {},
                    ).items():
                        if debugApi:
                            fieldinfo['source'] = f'opensearch.{templateName}.{componentName}'
                        if 'type' in fieldinfo:
                            fields[fieldname]['type'] = field_type_map[malcolm_utils.deep_get(fieldinfo, ['type'])]
                        if debugApi:
                            fields[fieldname]['original'] = fields[fieldname].get('original', []) + [fieldinfo]

    except Exception as e:
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting OpenSearch index template fields")

    # get fields from OpenSearch dashboards
    try:
        for field in (
            requests.get(
                f"{dashboardsUrl}/api/index_patterns/_fields_for_wildcard",
                params={
                    'pattern': index_from_args(args),
                    'meta_fields': ["_source", "_id", "_type", "_index", "_score"],
                },
                auth=opensearchReqHttpAuth,
                verify=opensearchSslVerify,
            )
            .json()
            .get('fields', [])
        ):
            if fieldname := malcolm_utils.deep_get(field, ['name']):
                if debugApi:
                    field['source'] = 'dashboards'
                field_types = malcolm_utils.deep_get(field, ['esTypes'], [])
                fields[fieldname]['type'] = field_type_map[
                    field_types[0] if len(field_types) > 0 else malcolm_utils.deep_get(fields[fieldname], ['type'])
                ]
                if debugApi:
                    fields[fieldname]['original'] = fields[fieldname].get('original', []) + [field]
    except Exception as e:
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting OpenSearch Dashboards index pattern fields")

    for fieldname in ("@version", "_source", "_id", "_type", "_index", "_score", "type"):
        fields.pop(fieldname, None)

    return jsonify(fields=fields, total=len(fields))


@app.route(f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/", methods=['GET'])
@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/version", methods=['GET']
)
def version():
    """Provides version information about Malcolm and the underlying OpenSearch instance

    Parameters
    ----------

    Returns
    -------
    version
        a string containing the Malcolm version (e.g., "5.2.0")
    machine
        the platform machine (e.g., x86_64)
    boot_time
        the UTC system boot time in ISO format
    built
        a string containing the Malcolm build timestamp (e.g., "2021-12-22T14:13:26Z")
    sha
        a string containing the last commit sha from the Malcolm source repository (e.g., "11540a7")
    opensearch
        a JSON structure containing basic OpenSearch version information
    opensearch_health
        a JSON structure containing OpenSearch cluster health
    """
    opensearchStats = requests.get(
        opensearchUrl,
        auth=opensearchReqHttpAuth,
        verify=opensearchSslVerify,
    ).json()
    if isinstance(opensearchStats, dict):
        opensearchStats['health'] = dict(databaseClient.cluster.health())

    return jsonify(
        version=app.config["MALCOLM_VERSION"],
        built=app.config["BUILD_DATE"],
        sha=app.config["VCS_REVISION"],
        mode=malcolm_utils.DatabaseModeEnumToStr(databaseMode),
        machine=platform.machine(),
        boot_time=datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat().replace('+00:00', 'Z'),
        opensearch=opensearchStats,
    )


@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/ready", methods=['GET']
)
def ready():
    """Return ready status (true or false) for various Malcolm components

    Parameters
    ----------

    Returns
    -------
    arkime
        true or false, the ready status of Arkime
    dashboards
        true or false, the ready status of Dashboards (or Kibana)
    dashboards_maps
        true or false, the ready status of the dashboards-helper offline map server
    filebeat_tcp
        true or false, the ready status of Filebeat's JSON-OVER-TCP
    freq
        true or false, the ready status of freq
    logstash_lumberjack
        true or false, the ready status of Logstash's lumberjack protocol listener
    logstash_pipelines
        true or false, the ready status of Logstash's pipelines
    netbox
        true or false, the ready status of NetBox
    opensearch
        true or false, the ready status of OpenSearch (or Elasticsearch)
    pcap_monitor
        true or false, the ready status of the PCAP monitoring process
    zeek_extracted_file_logger
        true or false, the ready status of the Zeek extracted file results logging process
    zeek_extracted_file_monitor
        true or false, the ready status of the Zeek extracted file monitoring process
    """
    try:
        arkimeResponse = requests.get(
            arkimeStatusUrl,
            verify=False,
        )
        arkimeResponse.raise_for_status()
        arkimeStatus = True
    except Exception as e:
        arkimeStatus = False
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting Arkime status")

    try:
        dashboardsStatus = requests.get(
            f'{dashboardsUrl}/api/status',
            auth=opensearchReqHttpAuth,
            verify=opensearchSslVerify,
        ).json()
    except Exception as e:
        dashboardsStatus = {}
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting Dashboards status")

    try:
        dashboardsMapsStatus = malcolm_utils.check_socket(dashboardsHelperHost, dashboardsMapsPort)
    except Exception as e:
        dashboardsMapsStatus = False
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting Logstash offline map server")

    try:
        filebeatTcpJsonStatus = malcolm_utils.check_socket(filebeatHost, filebeatTcpJsonPort)
    except Exception as e:
        filebeatTcpJsonStatus = False
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting filebeat TCP JSON listener status")

    try:
        freqResponse = requests.get(freqUrl)
        freqResponse.raise_for_status()
        freqStatus = True
    except Exception as e:
        freqStatus = False
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting freq status")

    try:
        logstashHealth = requests.get(f'{logstashUrl}/_health_report').json()
    except Exception as e:
        logstashHealth = {}
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting Logstash node status")

    try:
        logstashLJStatus = malcolm_utils.check_socket(logstashHost, logstashLJPort)
    except Exception as e:
        logstashLJStatus = False
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting Logstash lumberjack listener status")

    try:
        netboxStatus = requests.get(
            f'{netboxUrl}/api/status/?format=json',
            headers={"Authorization": f"Token {netboxToken}"} if netboxToken else None,
            verify=False,
        ).json()
    except Exception as e:
        netboxStatus = {}
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting NetBox status")

    try:
        openSearchHealth = dict(databaseClient.cluster.health())
    except Exception as e:
        openSearchHealth = {}
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting OpenSearch health")

    try:
        pcapMonitorStatus = malcolm_utils.check_socket(pcapMonitorHost, pcapTopicPort)
    except Exception as e:
        pcapMonitorStatus = False
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting PCAP monitor topic status")

    try:
        zeekExtractedFileMonitorStatus = malcolm_utils.check_socket(
            zeekExtractedFileMonitorHost, zeekExtractedFileTopicPort
        )
    except Exception as e:
        zeekExtractedFileMonitorStatus = False
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting Zeek extracted file monitor topic status")

    try:
        zeekExtractedFileLoggerStatus = malcolm_utils.check_socket(
            zeekExtractedFileLoggerHost, zeekExtractedFileLoggerTopicPort
        )
    except Exception as e:
        zeekExtractedFileLoggerStatus = False
        if debugApi:
            print(f"{type(e).__name__}: {str(e)} getting Zeek extracted file logger topic status")

    return jsonify(
        arkime=arkimeStatus,
        dashboards=(
            malcolm_utils.deep_get(
                dashboardsStatus,
                [
                    "status",
                    "overall",
                    "level" if databaseMode == malcolm_utils.DatabaseMode.ElasticsearchRemote else "state",
                ],
                "red",
            )
            != "red"
        ),
        dashboards_maps=dashboardsMapsStatus,
        filebeat_tcp=filebeatTcpJsonStatus,
        freq=freqStatus,
        logstash_lumberjack=logstashLJStatus,
        logstash_pipelines=(malcolm_utils.deep_get(logstashHealth, ["status"], "red") != "red")
        and (malcolm_utils.deep_get(logstashHealth, ["indicators", "pipelines", "status"], "red") != "red"),
        netbox=bool(isinstance(netboxStatus, dict) and netboxStatus.get('netbox-version')),
        opensearch=(malcolm_utils.deep_get(openSearchHealth, ["status"], 'red') != "red"),
        pcap_monitor=pcapMonitorStatus,
        zeek_extracted_file_logger=zeekExtractedFileLoggerStatus,
        zeek_extracted_file_monitor=zeekExtractedFileMonitorStatus,
    )


@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/dashboard-export/<dashid>",
    methods=['GET', 'POST'],
)
def dashboard_export(dashid):
    """Uses the opensearch dashboards API to export a dashboard. Also handles the _REPLACER strings
    as described in "Adding new visualizations and dashboards" at
    https://idaholab.github.io/Malcolm/docs/contributing-dashboards.html#DashboardsNewViz

    Parameters
    ----------
    dashid : string
        the ID of the dashboard to export
    request : Request
        Uses 'replace' from requests arguments, true (default) or false; indicates whether or not to do
        MALCOLM_NETWORK_INDEX_PATTERN_REPLACER, MALCOLM_NETWORK_INDEX_TIME_FIELD_REPLACER,
        MALCOLM_OTHER_INDEX_PATTERN_REPLACER

    Returns
    -------
    content
        The JSON of the exported dashboard
    """

    args = get_request_arguments(request)
    try:
        # call the API to get the dashboard JSON
        response = requests.get(
            f"{dashboardsUrl}/api/{'kibana' if (databaseMode == malcolm_utils.DatabaseMode.ElasticsearchRemote) else 'opensearch-dashboards'}/dashboards/export",
            params={
                'dashboard': dashid,
            },
            auth=opensearchReqHttpAuth,
            verify=opensearchSslVerify,
        )
        response.raise_for_status()

        if doReplacers := malcolm_utils.str2bool(args.get('replace', 'true')):
            # replace references to index pattern names with the _REPLACER strings, which will allow other Malcolm
            #   instances that use different index pattern names to import them and substitute their own names
            replacements = {
                app.config['MALCOLM_NETWORK_INDEX_PATTERN']: 'MALCOLM_NETWORK_INDEX_PATTERN_REPLACER',
                app.config['MALCOLM_NETWORK_INDEX_TIME_FIELD']: 'MALCOLM_NETWORK_INDEX_TIME_FIELD_REPLACER',
                app.config['MALCOLM_OTHER_INDEX_PATTERN']: 'MALCOLM_OTHER_INDEX_PATTERN_REPLACER',
            }
            pattern = re.compile('|'.join(re.escape(key) for key in replacements))
            responseText = pattern.sub(lambda match: replacements[match.group(0)], response.text)
        else:
            # ... or just return it as-is
            responseText = response.text

        # remove index pattern definition from exported dashboard as they get created programatically
        #   on Malcolm startup and we don't want them to come in with imported dashboards
        if responseParsed := malcolm_utils.LoadStrIfJson(responseText):
            if 'objects' in responseParsed and isinstance(responseParsed['objects'], list):
                responseParsed['objects'] = [
                    o
                    for o in responseParsed['objects']
                    if not (
                        (o.get("type") == "index-pattern")
                        and (
                            o.get("id")
                            in [
                                (
                                    "MALCOLM_NETWORK_INDEX_PATTERN_REPLACER"
                                    if doReplacers
                                    else app.config['MALCOLM_NETWORK_INDEX_PATTERN']
                                ),
                                (
                                    "MALCOLM_OTHER_INDEX_PATTERN_REPLACER"
                                    if doReplacers
                                    else app.config['MALCOLM_OTHER_INDEX_PATTERN']
                                ),
                            ]
                        )
                    )
                ]
            return jsonify(responseParsed)

        else:
            # what we got back from the API wasn't valid JSON, so sad
            return jsonify(error=f'Could not process export response for {dashid}')

    except Exception as e:
        errStr = f"{type(e).__name__}: {str(e)} exporting OpenSearch Dashboard {dashid}"
        if debugApi:
            print(errStr)
        return jsonify(error=errStr)


@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/ingest-stats",
    methods=['GET'],
)
def ingest_stats():
    """Provide an aggregation of each log source (host.name) with it's latest event.ingested
    time. This can be used to know the most recent time a document was written from each
    network sensor.

    Parameters
    ----------
    request : Request
        Uses 'doctype' from request arguments
    Returns
    -------
    fields
        A dict where "sources" contains a sub-dict where key is host.name and value is max(event.ingested)
        for that host, and "latest_ingest_age_seconds" is the age (in seconds) of the most recently
        ingested log
    """
    result = {}
    result['latest_ingest_age_seconds'] = 0
    try:
        # do the aggregation bucket query for the max event.ingested value for each data source
        request_args = get_request_arguments(request)
        s = (
            SearchClass(
                using=databaseClient,
                index=index_from_args(request_args),
            ).extra(size=0)
            # Exclusions:
            #   NGINX access and error logs: we want to exclude nginx error and
            #       access logs, otherwise the very act of accessing Malcolm will
            #       update the latest ingest time returned from this function.
            #   event() webhook: we want to exclude alerts written by the event()
            #       webhook API (see below) and limit our results to actual
            #       network logs ingested via PCAP, etc.
            .query(
                QueryClass(
                    'bool',
                    must_not=[
                        QueryClass(
                            'term',
                            **{
                                'event.module': (
                                    'nginx' if doctype_is_host_logs(doctype_from_args(request_args)) else 'alerting'
                                )
                            },
                        )
                    ],
                )
            )
        )

        hostAgg = AggregationClass('terms', field='host.name')
        maxIngestAgg = AggregationClass('max', field='event.ingested')
        s.aggs.bucket('host_names', hostAgg).metric('max_event_ingested', maxIngestAgg)
        response = s.execute()

        # put the result array together while tracking the most recent ingest time
        nowTime = datetime.now().astimezone(timezone.utc)
        maxTime = None
        result['sources'] = {}
        for bucket in response.aggregations.host_names.buckets:
            sourceTime = datetime.fromtimestamp(bucket.max_event_ingested.value / 1000, timezone.utc)
            result['sources'][bucket.key] = sourceTime.replace(microsecond=0).isoformat()
            if (maxTime is None) or (sourceTime > maxTime):
                maxTime = sourceTime

        # calculate the age of the most recent ingest time
        if maxTime:
            diffTime = nowTime - maxTime
            result['latest_ingest_age_seconds'] = max(round(diffTime.total_seconds()), 0)

    except Exception as e:
        if debugApi:
            print(f"{type(e).__name__}: \"{str(e)}\" getting ingest stats")

    return jsonify(result)


@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/netbox-sites",
    methods=['GET'],
)
def netbox_sites():
    """Query the NetBox API and return its sites

    Parameters
    ----------

    Returns
    -------
    sites
        A dict where the key is the netbox site ID and the value is a dict containing 'name', 'display', and 'slug'.
        Example:
            {
                231: {"name": "Site1", "display": "Site One", "slug": "site1"},
                232: {"name": "Site2", "display": "Site Two", "slug": "site2"},
                ...
            }

    """
    result = {}
    try:
        headers = {"Authorization": f"Token {netboxToken}"} if netboxToken else None
        url = f'{netboxUrl}/api/dcim/sites/?format=json'
        while url:
            try:
                response = requests.get(url, headers=headers, verify=False)
                response.raise_for_status()
            except Exception as e:
                if debugApi:
                    print(f"{type(e).__name__}: \"{str(e)}\" getting NetBox sites")
                break
            if response and (data := response.json()):
                result.update(
                    {
                        site["id"]: {"name": site.get("name"), "display": site.get("display"), "slug": site.get("slug")}
                        for site in data.get("results", [])
                    }
                )
                url = data.get("next")
            else:
                break

    except Exception as e:
        if debugApi:
            print(f"{type(e).__name__}: \"{str(e)}\" getting NetBox sites")

    return jsonify(result)


@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/ping", methods=['GET']
)
def ping():
    """Says 'pong' (for a simple health check)

    Parameters
    ----------

    Returns
    -------
    pong
        a string containing 'pong'
    """
    return jsonify(ping="pong")


@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/alert", methods=['POST']
)
@app.route(
    f"{('/' + app.config['MALCOLM_API_PREFIX']) if app.config['MALCOLM_API_PREFIX'] else ''}/event", methods=['POST']
)
def event():
    """Webhook that accepts alert data (like that from the OpenSearch Alerting API) to be
    reindexed into OpenSearch as session records for viewing in Malcolm's default visualizations.

    See Malcolm's malcolm_api_loopback_monitor.json and malcolm_api_loopback_destination.json
    for formatting template examples.

    Parameters
    ----------
    HTTP POST data in JSON format
    e.g.:
        {
          "alert": {
            "monitor": {
              "name": "Malcolm API Loopback Monitor"
            },
            "trigger": {
              "name": "Malcolm API Loopback Trigger",
              "severity": 4
            },
            "period": {
              "start": "2022-03-08T18:03:30.576Z",
              "end": "2022-03-08T18:04:30.576Z"
            },
            "results": [
              {
                "_shards": {
                  "total": 5,
                  "failed": 0,
                  "successful": 5,
                  "skipped": 0
                },
                "hits": {
                  "hits": [],
                  "total": {
                    "value": 697,
                    "relation": "eq"
                  },
                  "max_score": null
                },
                "took": 1,
                "timed_out": false
              }
            ],
            "body": "",
            "alert": "PLauan8BaL6eY1yCu9Xj",
            "error": ""
          }
        }

    Returns
    -------
    status
        the JSON-formatted OpenSearch response from indexing/updating the alert record
    """
    alert = {}
    idxResponse = {}
    data = get_request_arguments(request)
    nowTimeStr = datetime.now().astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
    if 'alert' in data:
        alert[app.config["MALCOLM_NETWORK_INDEX_TIME_FIELD"]] = malcolm_utils.deep_get(
            data,
            [
                'alert',
                'period',
                'start',
            ],
            nowTimeStr,
        )
        alert['firstPacket'] = alert[app.config["MALCOLM_NETWORK_INDEX_TIME_FIELD"]]
        alert['lastPacket'] = malcolm_utils.deep_get(
            data,
            [
                'alert',
                'period',
                'end',
            ],
            nowTimeStr,
        )
        alert['ecs'] = {}
        alert['ecs']['version'] = '1.6.0'
        alert['event'] = {}
        alert['event']['kind'] = 'alert'
        alert['event']['start'] = alert['firstPacket']
        alert['event']['end'] = alert['lastPacket']
        alert['event']['ingested'] = nowTimeStr
        alert['event']['provider'] = 'malcolm'
        alert['event']['dataset'] = 'alerting'
        alert['event']['module'] = 'alerting'
        alert['event']['url'] = '/dashboards/app/alerting#/dashboard'
        alertId = malcolm_utils.deep_get(
            data,
            [
                'alert',
                'alert',
            ],
        )
        alert['event']['id'] = alertId if alertId else random_id()
        if alertBody := malcolm_utils.deep_get(
            data,
            [
                'alert',
                'body',
            ],
        ):
            alert['event']['original'] = alertBody
        if triggerName := malcolm_utils.deep_get(
            data,
            [
                'alert',
                'trigger',
                'name',
            ],
        ):
            alert['event']['reason'] = triggerName
        if monitorName := malcolm_utils.deep_get(
            data,
            [
                'alert',
                'monitor',
                'name',
            ],
        ):
            alert['rule'] = {}
            alert['rule']['name'] = monitorName
        if alertSeverity := str(
            malcolm_utils.deep_get(
                data,
                [
                    'alert',
                    'trigger',
                    'severity',
                ],
            )
        ):
            sevnum = 100 - ((int(alertSeverity) - 1) * 20) if alertSeverity.isdigit() else 40
            alert['event']['risk_score'] = sevnum
            alert['event']['risk_score_norm'] = sevnum
            alert['event']['severity'] = sevnum
            alert['event']['severity_tags'] = 'Alert'
        if alertResults := malcolm_utils.deep_get(
            data,
            [
                'alert',
                'results',
            ],
        ):
            if len(alertResults) > 0:
                if hitCount := malcolm_utils.deep_get(alertResults[0], ['hits', 'total', 'value'], 0):
                    alert['event']['hits'] = hitCount

        docDateStr = dateparser.parse(alert[app.config["MALCOLM_NETWORK_INDEX_TIME_FIELD"]]).strftime('%y%m%d')
        idxResponse = databaseClient.index(
            index=f"{app.config['MALCOLM_NETWORK_INDEX_PATTERN'].rstrip('*')}{docDateStr}",
            id=f"{docDateStr}-{alert['event']['id']}",
            body=alert,
        )

    if debugApi:
        print(json.dumps(data))
        print(json.dumps(alert))
        print(json.dumps(idxResponse))
    return jsonify(result=idxResponse)


@app.errorhandler(Exception)
def basic_error(e):
    """General exception handler for the app

    Parameters
    ----------

    Returns
    -------
    error
        The type of exception and its string representation (e.g., "KeyError: 'protocols'")
    """
    errorStr = f"{type(e).__name__}: {str(e)}"
    if debugApi:
        print(errorStr)
        print(traceback.format_exc())
    return jsonify(error=errorStr)
