# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import subprocess
import json
import os
import pwd


def get_compose_file():
    # 1. Check env var
    env_path = os.getenv("MALCOLM_COMPOSE_FILE")
    if env_path and os.path.isfile(env_path):
        return env_path

    # 2. Lookup the home directory of main user
    uid_to_use = 1000 if os.geteuid() == 0 else os.geteuid()
    try:
        if (main_user_home_dir := pwd.getpwuid(uid_to_use).pw_dir) and os.path.isdir(main_user_home_dir):
            # 3. Construct fallback path
            compose_file = os.path.join(main_user_home_dir, "Malcolm", "docker-compose.yml")
            if os.path.isfile(compose_file):
                return compose_file
    except Exception:
        raise RuntimeError("Unable to determine path to Malcolm docker-compose.yml")

    return None


def service(command):
    if isinstance(command, str) and (command := command.split(" ")):
        command[0] = os.path.join('scripts', command[0])

    if command and (compose_file := get_compose_file()):
        original_cwd = os.getcwd()
        os.chdir(os.path.dirname(compose_file))
        try:
            p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            retcode = p.wait()
            out, err = p.communicate()
            out_str = out.decode("utf-8").strip()
            err_str = err.decode("utf-8").strip()
            if retcode == 0:
                return {"success": True, "output": out_str if out_str else "Success"}
            else:
                return {
                    "success": False,
                    "cmd": command,
                    "returncode": retcode,
                    "out": out_str,
                    "err": err_str,
                }

        except Exception as e:
            return json.dumps({"cmd": command, "err": str(e)})
        finally:
            os.chdir(original_cwd)
