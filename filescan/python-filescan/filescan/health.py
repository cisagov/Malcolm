from __future__ import annotations

from filescan import logging

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger(__name__)

import os
import supervisor.childutils

from flask import Flask, redirect, url_for
from pydantic import BaseModel
from typing import Any, Final, cast, Literal


app = Flask(__name__)

try:
    rpc = supervisor.childutils.getRPCInterface(os.environ)
except Exception as e:
    log.exception('unable to open supervisor XML-RPC interface')
    rpc = None
else:
    log.info('opened supervisor XML-RPC interface')
    log.info('supervisor version: %s', rpc.supervisor.getSupervisorVersion())


type SupervisorHealth = Literal[
    'healthy',
    'unhealthy',
    'error',
]
type SupervisorState = Literal[
    'unknown',
    'fatal',
    'running',
    'restarting',
    'shutdown',
]
type ProcessState = Literal[
    'stopped',
    'starting',
    'running',
    'backoff',
    'stopping',
    'exited',
    'fatal',
    'unknown',
]


class State(BaseModel):
    health: SupervisorHealth = 'healthy'
    state: SupervisorState = 'unknown'
    version: str | None = None
    programs: dict[str, list[Program]] = {}
    error: str | None = None


class Program(BaseModel):
    name: str
    state: ProcessState
    spawnerr: str | None = None
    exitstatus: int | None = None
    start: int | None = None
    stop: int | None = None
    healthy: bool | None = None


HAS_STARTED: Final = {'RUNNING', 'EXITED', 'FATAL', 'BACKOFF', 'STOPPING'}
NOT_RUNNING: Final = {'STOPPED', 'EXITED', 'FATAL', 'BACKOFF'}
ERRORED: Final = {'FATAL', 'BACKOFF', 'UNKNOWN'}


@app.route('/')
def root() -> Any:
    return redirect(url_for('health'), code=302)


@app.route('/health')
def health() -> Any:
    result = State()

    try:
        if rpc is None:
            raise RuntimeError('unable to open supervisor XML-RPC interface')

        version: str = cast(str, rpc.supervisor.getSupervisorVersion())
        state: SupervisorState = cast(dict, rpc.supervisor.getState())['statename'].lower()
        config: list[dict] = cast(list[dict], rpc.supervisor.getAllConfigInfo())
        procs: list[dict] = cast(list[dict], rpc.supervisor.getAllProcessInfo())
        programs: dict[str, list[Program]] = {}

        for cfg, proc in zip(
            sorted(config, key=lambda e: e['name']),
            sorted(procs, key=lambda e: e['name']),
        ):
            prog = Program(
                name=proc['name'],
                state=proc['statename'].lower(),
                spawnerr=(proc.get('spawnerr') or None),
            )

            if prog.state in HAS_STARTED:
                prog.start = proc['start']
            if prog.state in NOT_RUNNING:
                if prog.start:
                    prog.stop = proc['end']
                    prog.exitstatus = proc['exitstatus']
            if (
                (prog.state in ERRORED)
                or (prog.stop and (prog.exitstatus not in cfg['exitcodes']))
                or (cfg['autostart'] and prog.state != 'running')
            ):
                prog.healthy = False
                result.health = 'unhealthy'
            elif prog.state == 'running':
                prog.healthy = True

            programs.setdefault(
                proc['group'],
                [],
            ).append(prog)

    except Exception as e:
        log.exception('failed to get supervisor/process states')
        result.health = 'error'
        result.error = str(e)

    else:
        result.version = version
        result.state = state
        result.programs.update(programs)

    return result.model_dump(exclude_none=True)


@app.errorhandler(404)
def page_not_found(_) -> Any:
    return 'page not found', 404
