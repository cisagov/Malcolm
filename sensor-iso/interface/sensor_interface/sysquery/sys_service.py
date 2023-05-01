# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

import subprocess
import json
import os

# traverse back up the path of the project directory to the scripts location
path = os.path.join(os.path.sep.join(__file__.split(os.path.sep)[:-3]), "sensor_ctl")


def service(command):
    # TODO implement better error handling

    command, arguement = command.split(" ")

    command_line = os.path.join(path, command)

    print(command_line, arguement)

    p = subprocess.Popen([command_line, arguement], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    retcode = p.wait()
    out, err = p.communicate()

    if not retcode:
        return json.dumps(out.decode("utf-8"))
    else:
        return json.dumps(
            {"cmd": [command_line], "returncode": retcode, "out": out.decode("utf-8"), "err": err.decode("utf-8")}
        )
