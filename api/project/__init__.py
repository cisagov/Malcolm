import dateparser
import opensearch_dsl
import opensearchpy
import os
import requests
import warnings

from datetime import datetime
from flask import Flask, jsonify, request
from opensearch_dsl import Search

warnings.filterwarnings(
    "ignore",
    message="The localize method is no longer necessary, as this time zone supports the fold attribute",
)

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config.from_object("project.config.Config")
opensearch_dsl.connections.create_connection(hosts=[app.config["OPENSEARCH_URL"]])


def gettimes(args):
    """Parses 'from' and 'to' times out of the provided dictionary, returning
    two datetime objects

    Parameters
    ----------
    args : dict
        The dictionary which should contain 'from' and 'to' times. Missing
        times are returned as None. e.g., gettimes(request.args). Times
        can be UNIX time integers represented as strings or strings
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


def filtertime(search, args):
    """Applies a time filter (inclusive; extracted from request arguments) to an OpenSearch query and
    returns the range as a tuple of integers representing the milliseconds since EPOCH. If
    either end of the range is unspecified, the start and end times default to "1 day ago" and "now",
    respectively.

    Parameters
    ----------
    search : opensearch_dsl.Search
        The object representing the OpenSearch Search query
    args : dict
        The dictionary which should contain 'from' and 'to' times (see gettimes)

    Returns
    -------
    return start_time, end_time
        integers representing the start and end times for the query, in milliseconds since the epoch
    """
    start_time, end_time = gettimes(args)
    start_time_ms = int(
        start_time.timestamp() * 1000 if start_time is not None else dateparser.parse("1 day ago").timestamp() * 1000
    )
    end_time_ms = int(end_time.timestamp() * 1000 if end_time is not None else datetime.now().timestamp() * 1000)
    search.filter(
        "range",
        **{
            app.config["ARKIME_INDEX_TIME_FIELD"]: {
                "gte": start_time_ms,
                "lte": end_time_ms,
                "format": "epoch_millis",
            }
        },
    )
    return start_time_ms, end_time_ms


def bucketfield(bucketname, fieldname, current_request):
    """Returns a bucket aggregation for a particular field over a given time range

    Parameters
    ----------
    bucketname : string
        The name of the "bucket" aggregation (not currently displayed in output)
    fieldname : string
        The name of the field on which to perform the aggregation
    current_request : Request
        The flask Request object being processed (see gettimes and filtertime)
        Uses 'from', 'to', and 'limit' from current_request.args

    Returns
    -------
    values
        list of dicts containing key and doc_count for each bucket
    range
        start_time (seconds since EPOCH) and end_time (seconds since EPOCH) of query
    """
    s = Search(using=opensearch_dsl.connections.get_connection(), index=app.config["ARKIME_INDEX_PATTERN"]).extra(
        size=0
    )
    start_time_ms, end_time_ms = filtertime(s, current_request.args)
    s.aggs.bucket(
        bucketname,
        "terms",
        field=fieldname,
        size=int(current_request.args["limit"]) if "limit" in current_request.args else app.config["RESULT_SET_LIMIT"],
    )

    response = s.execute()
    return jsonify(
        values=response.aggregations.to_dict()[bucketname]["buckets"],
        range=(start_time_ms // 1000, end_time_ms // 1000),
    )


@app.route("/protocols")
@app.route("/services")
def protocols():
    """Returns the protocols found in network data for a specified period

    Parameters
    ----------
    request : Request
        see bucketfield

    Returns
    -------
    values
        list of dicts containing key and doc_count for each bucket
    range
        start_time (seconds since EPOCH) and end_time (seconds since EPOCH) of query
    """

    return bucketfield("protocols", "network.protocol", request)


@app.route("/tags")
def tags():
    """Returns the tags applied to network data for a specified period

    Parameters
    ----------
    request : Request
        see bucketfield

    Returns
    -------
    values
        list of dicts containing key and doc_count for each bucket
    range
        start_time (seconds since EPOCH) and end_time (seconds since EPOCH) of query
    """

    return bucketfield("tags", "tags", request)


@app.route("/severity-tags")
def severity_tags():
    """Returns the severity tags applied to network data for a specified period

    Parameters
    ----------
    request : Request
        see bucketfield

    Returns
    -------
    values
        list of dicts containing key and doc_count for each bucket
    range
        start_time (seconds since EPOCH) and end_time (seconds since EPOCH) of query
    """

    return bucketfield("severity-tags", "event.severity_tags", request)


@app.route("/indices")
def indices():
    """Provide a list of indices in the OpenSearch data store

    Parameters
    ----------

    Returns
    -------
    indices
        The output of _cat/indices?format=json from the OpenSearch API
    """
    return jsonify(indices=requests.get(f'{app.config["OPENSEARCH_URL"]}/_cat/indices?format=json').json())


@app.route("/")
@app.route("/version")
def version():
    """Provides version information about Malcolm and the underlying OpenSearch instance

    Parameters
    ----------

    Returns
    -------
    version
        a string containing the Malcolm version (e.g., "5.1.0")
    built
        a string containing the Malcolm build timestamp (e.g., "2021-12-22T14:13:26Z")
    sha
        a string containing the last commit sha from the Malcolm source repository (e.g., "11540a7")
    opensearch
        a JSON structure containing basic OpenSearch version information
    opensearch_health
        a JSON structure containing OpenSearch cluster health
    """
    return jsonify(
        version=app.config["MALCOLM_VERSION"],
        built=app.config["BUILD_DATE"],
        sha=app.config["VCS_REVISION"],
        opensearch=requests.get(app.config["OPENSEARCH_URL"]).json(),
        opensearch_health=opensearch_dsl.connections.get_connection().cluster.health(),
    )


@app.route("/ping")
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
    return jsonify(error=f"{type(e).__name__}: {str(e)}")
