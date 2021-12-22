import os
import opensearchpy
import opensearch_dsl
import requests
import warnings

import dateparser
from datetime import datetime
from opensearch_dsl import Search

from flask import Flask, jsonify, send_from_directory, request, redirect, url_for

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


@app.route("/protocols")
@app.route("/services")
def protocols():
    """Returns the protocols found in network data for a specified period

    Parameters
    ----------
    from : string
        The beginning of the time period (see gettimes for format)
    to : string
        The ending of the time period (see gettimes for format)

    Returns
    -------
    return json
        jsonified OpenSearch result set containing protocols
    """
    start_time, end_time = gettimes(request.args)

    s = Search(using=opensearch_dsl.connections.get_connection(), index=app.config["ARKIME_INDEX_PATTERN"]).extra(
        size=0
    )
    s.aggs.bucket("protocols", "terms", field="network.protocol", size=app.config["RESULT_SET_LIMIT"])

    response = s.execute()
    return jsonify(protocols=response.aggregations.to_dict()["protocols"]["buckets"])


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
