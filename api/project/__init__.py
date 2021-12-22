import os
import opensearchpy
import opensearch_dsl
import requests
import warnings

import dateparser
from datetime import datetime

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
    start_time, end_time = gettimes(request.args)
    return jsonify(
        start_time=start_time.strftime("%Y/%m/%d %H:%M:%S") if start_time else "",
        end_time=end_time.strftime("%Y/%m/%d %H:%M:%S") if end_time else "",
    )


@app.route("/indices")
def indices():
    return jsonify(indices=requests.get(f'{app.config["OPENSEARCH_URL"]}/_cat/indices?format=json').json())


@app.route("/")
@app.route("/version")
def version():
    return jsonify(
        version=app.config["MALCOLM_VERSION"],
        built=app.config["BUILD_DATE"],
        sha=app.config["VCS_REVISION"],
        opensearch=requests.get(app.config["OPENSEARCH_URL"]).json(),
        opensearch_health=opensearch_dsl.connections.get_connection().cluster.health(),
    )


@app.route("/ping")
def ping():
    return jsonify(ping="pong")
