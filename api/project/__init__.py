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
app.config.from_object("project.config.Config")


@app.route("/")
def hello_world():
    return jsonify(hello=app.config["HELLO_WORLD"])
