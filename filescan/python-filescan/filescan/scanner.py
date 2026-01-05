from __future__ import annotations

from filescan import logging

log = logging.getLogger(__name__)

import anyio
import sys
import redis.exceptions
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from filescan.click import click
from filescan.config import BaseConfig
from filescan.model import ScanRequest, ScanResult, ScanTimeout, ScanEnd, ScanBegin
from pathlib import Path
from pydantic import BaseModel
from redis.asyncio import Redis
from typing import Any, ClassVar


class ScannerOptions(BaseModel, frozen=True):
    timeout: float = 900.0


@dataclass
class Scanner[GC: BaseConfig, SC: ScannerOptions](metaclass=ABCMeta):
    scanner_name: ClassVar[str]
    config_class: ClassVar[type[BaseConfig]]

    global_config: GC
    scanner_config: SC
    connection: Redis

    async def handle_request(self, request: ScanRequest) -> None:
        log.info('received request for %s', request.id)
        try:
            begin = request.get_begin(self.scanner_name)
            await self.notify(begin)

            end = None
            result = None

            try:
                with anyio.fail_after(self.scanner_config.timeout):
                    response = await self.scan(request)
                result = begin.get_result(response)
            except anyio.get_cancelled_exc_class():
                raise
            except TimeoutError:
                log.error('scan timed out for %s', request.id)
                result = begin.get_result(error='scan timed out')
                end = begin.get_timeout()
            except Exception as e:
                log.exception('scan failed for %s', request.id)
                result = begin.get_result(error=str(e))

            await self.send_result(result)
            await self.notify(end or begin.get_end())

        except anyio.get_cancelled_exc_class():
            pass

    async def notify(self, note: ScanBegin | ScanEnd | ScanTimeout) -> None:
        log.debug('sending notification: %r', note)
        await self.connection.publish(
            self.global_config.redis.keys.notify,
            note.model_dump_json(),
        )

    async def send_result(self, result: ScanResult) -> None:
        log.debug('sending result: %r', result)
        log.info('sending result for %s', result.id)
        await self.connection.publish(
            self.global_config.redis.keys.result,
            result.model_dump_json(),
        )

    async def process_requests(self) -> None:
        try:
            pubsub = self.connection.pubsub()
            gc = self.global_config
            keys = {gc.redis.keys.request}
            log.info(
                'subscribing to keys: %s:%d/%d => {%s}',
                gc.redis.host,
                gc.redis.port,
                gc.redis.db,
                ', '.join(keys),
            )
            await pubsub.subscribe(*keys)

            log.info('waiting for scan requests...')
            async with anyio.create_task_group() as group:
                while True:
                    msg = await pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=5.0,
                    )
                    try:
                        if not msg or msg.get('type') != 'message' or not (data := msg.get('data')):
                            await anyio.sleep(0.1)
                            continue
                        request = ScanRequest.model_validate_json(data)
                    except:
                        log.exception('failed to parse request')
                        continue
                    group.start_soon(self.handle_request, request)

        except anyio.get_cancelled_exc_class():
            pass

    @abstractmethod
    async def scan(self, request: ScanRequest) -> Any: ...


def scanner_main(
    scanner_class: type[Scanner],
    *,
    version: str | None = None,
) -> click.Command:
    if version is None:
        script = sys.modules.get('__main__', None)
        version = getattr(script, '__version__', None)

    @click.command()
    @click.version_option(version, help="print the version of this tool and exit")
    @click.option("--verbose", "-v", count=True, help="increase logging verbosity (may be repeated)")
    @click.option("--quiet/--no-quiet", "-q", help="run silently except for critical errors")
    @click.option(
        "--config",
        "-c",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="specify a config file to load",
    )
    async def main(
        verbose: int,
        quiet: bool,
        config: Path | None,
    ) -> None:
        # setup logging properly as early as possible
        logging.basicConfig(verbosity=verbose, quiet=quiet, force=True)
        # get an options object, one way or another
        if config:
            options = scanner_class.config_class.from_path(config)
        else:
            log.warning('no config file specified, this is probably not what ' 'you want! continuing anyway...')
            options = scanner_class.config_class()

        try:
            await anyio.sleep(0.5)
            try:
                connection = Redis(
                    host=options.redis.host,
                    port=options.redis.port,
                    db=options.redis.db,
                    username=options.redis.username,
                    password=options.redis.password,
                    decode_responses=True,
                    client_name=Path(sys.argv[0]).stem,
                )
                await connection.ping()
            except redis.exceptions.ConnectionError as exc:
                # log the error, but don't print a novel
                exc.__suppress_context__ = True
                log.debug(
                    'failed to open redis connection',
                    exc_info=True,
                )
                log.fatal(
                    'unable to open redis connection: %s:%d/%d',
                    options.redis.host,
                    options.redis.port,
                    options.redis.db,
                )
                # this is an error we can't really recover from
                sys.exit(1)

            async with anyio.create_task_group() as group:
                scanner = scanner_class(
                    options,
                    getattr(options, scanner_class.scanner_name),
                    connection,
                )
                group.start_soon(scanner.process_requests)

                await anyio.sleep_forever()

        except anyio.get_cancelled_exc_class():
            pass

    return main()
