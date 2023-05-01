# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

import psutil
import time
import json
import logging
import os
from .sysquery import sys_service as sys_s
from flask import render_template, send_from_directory
from flask import Flask
from flask_cors import CORS

'''
    Application Configuration
'''
APP_ROOT = os.path.dirname(os.path.abspath(__file__))  # refers to application_top
APP_STATIC = os.path.join(APP_ROOT, 'static')

app = Flask(__name__)
CORS(app)

'''
    Logging configuration
    Purpose: Remove the GET requests and other things to just error level records
'''
# logging.getLogger('flask_cors').level = logging.DEBUG
# log = logging.getLogger('werkzeug')
# log.setLevel(logging.ERROR)

'''
    Time Setup
    int = seconds
'''
period = 1

'''
    Web Pages
'''


@app.route('/')
def index():
    return render_template('system_block.html')


@app.route('/buttons')
def buttons():
    return render_template('buttons.html')


'''
    Services
'''


@app.route('/script_call/<string:script>', methods=['POST'])
def activate_service(script):
    print(script)
    return sys_s.service(script)


'''
    System Queries
'''


@app.route('/update', methods=['GET'])
def update_stats():
    req_time = int(time.time())

    disk_write_data_start = psutil.disk_io_counters(perdisk=False)
    io_data_start = psutil.net_io_counters()

    # Some metrics are only reported in values since uptime,
    # so sample over a period (in seconds) to get rate.

    time.sleep(period)

    cpu_data = psutil.cpu_percent(interval=None)
    ram_data = psutil.virtual_memory()

    # contains all disk data (with total size >= 1GB)
    disks_data = list(
        filter(
            lambda y: y[1][0] >= 1000000000,
            [(x.mountpoint, psutil.disk_usage(x.mountpoint)) for x in psutil.disk_partitions()],
        )
    )

    disks_idx = (req_time // 6) % len(disks_data)

    # contains "currently displayed" disk data (cycles based on time)
    disk_mount = disks_data[disks_idx][0]
    disk_data = disks_data[disks_idx][1]

    disk_write_data = psutil.disk_io_counters(perdisk=False)
    io_data = psutil.net_io_counters()

    data = {
        'cpu': {'percent': cpu_data},
        'ram': {'percent': ram_data[2], 'total': ram_data[0], 'used': ram_data[3]},
        'disks': [],  # todo: work in progress
        'disk': {'mount': disk_mount, 'total': disk_data[0], 'used': disk_data[1], 'percent': disk_data[3]},
        'disk_io': {
            'read_bytes_sec': (disk_write_data[2] - disk_write_data_start[2]) / period,
            'write_bytes_sec': (disk_write_data[3] - disk_write_data_start[3]) / period,
        },
        'net_io': {
            'sent_bytes_sec': (io_data[0] - io_data_start[0]) / period,
            'received_bytes_sec': (io_data[1] - io_data_start[1]) / period,
        },
    }
    for disk_data in disks_data:
        data['disks'].append(
            {'mount': disk_data[0], 'total': disk_data[1][0], 'used': disk_data[1][1], 'percent': disk_data[1][3]}
        )

    return json.dumps(data)


'''
    Javascript servicing
'''


@app.route('/load', methods=['GET'])
def read_dash():
    with open(os.path.join(APP_STATIC, 'dashboard/dashboard.json')) as f:
        data = json.load(f)

    return json.dumps(data)


@app.route('/plugins/thirdparty/<path:filename>')
def serve_static(filename):
    dir = os.path.join(APP_STATIC, 'js')
    return send_from_directory(dir, filename)


if __name__ == "__main__":
    app.run()
