import os

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


@app.route('/')
@app.route('/version')
def index():
  return jsonify(
    version=app.config["MALCOLM_VERSION"],
    built=app.config["BUILD_DATE"],
    sha=app.config["VCS_REVISION"],
  )
