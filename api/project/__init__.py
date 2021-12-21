import os
import opensearchpy
import opensearch_dsl
import requests

from flask import (
  Flask,
  jsonify,
  send_from_directory,
  request,
  redirect,
  url_for
)

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config.from_object("project.config.Config")
opensearch_dsl.connections.create_connection(hosts=[app.config["OPENSEARCH_URL"]])


@app.route('/')
@app.route('/version')
def index():
  return jsonify(
    version=app.config["MALCOLM_VERSION"],
    built=app.config["BUILD_DATE"],
    sha=app.config["VCS_REVISION"],
    opensearch=requests.get(app.config["OPENSEARCH_URL"]).json(),
    opensearch_health=opensearch_dsl.connections.get_connection().cluster.health()
  )
