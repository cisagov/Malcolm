from __future__ import annotations

from typing import Any, Final, TYPE_CHECKING, Iterator
import logging
import os
import re
import string
import pathlib
import asyncio
import threading
import inflection
import dataclasses

if TYPE_CHECKING:
    from _typeshed import SupportsWrite
else:
    type SupportsWrite[T] = "_typeshed.SupportsWrite[T]"

from logging import (
    critical as critical,
    CRITICAL as CRITICAL,
    debug as debug,
    DEBUG as DEBUG,
    error as error,
    ERROR as ERROR,
    NOTSET as NOTSET,
    exception as exception,
    getLogger as getLogger,
    getLevelNamesMapping as getLevelNamesMapping,
    info as info,
    INFO as INFO,
    Logger as BaseLogger,
    LoggerAdapter as BaseLoggerAdapter,
    LogRecord as BaseLogRecord,
    root as root,
    StreamHandler as BaseStreamHandler,
    FileHandler as BaseFileHandler,
    warning as warning,
    WARNING as WARNING,
)

__all__ = (
    "BaseLogRecord", "BaseStreamHandler", "critical", "CRITICAL", "debug",
    "DEBUG", "error", "ERROR", "exception", "getLogger", "info", "INFO",
    "Logger", "LogRecord", "StreamHandler", "warning", "WARNING",
)


DEFAULT_FORMAT: Final = {
    "%": " ".join([
        "%(asctime)s", "│",
        "%(levelicon)s",
        "%(processName)-12s",
        #"%(workerName)-16s",
        "%(message)s",
    ]),
    "{": " ".join([
        "{asctime:s}", "│",
        "{levelicon:s}",
        "{processName:<12s}",
        #"{workerName:<16s}",
        "{message:s}",
    ]),
    "$": " ".join([
        "${asctime}", "│",
        "${levelicon}",
        "${processName}",
        #"${workerName}",
        "${message}",
    ]),
}
DEFAULT_DATEFMT: Final = "%Y-%m-%d %H:%M:%S"
DEFAULT_WORKER_NAME: Final = "<main>"
SUPERVISOR_PROCESS_NAME: Final = os.getenv("SUPERVISOR_PROCESS_NAME", None)


PERCENT_RE: Final = re.compile(r"""
    %
    (?:\((?P<key>[A-Za-z_][A-Za-z0-9_]*)\))?
    (?P<flags>[-#0 +]+)?
    (?P<width>0|[1-9][0-9]*|\*)?
    (?:\.(?P<precision>0|[1-9][0-9]*|\*))?
    (?P<size>[hlL]+)?
    (?P<type>[diouxXeEfFgGcrsa])
""", re.VERBOSE)

PLURAL_RE: Final = re.compile(rf"""
    ^
    (\ +)
    (\w+)\(e?s\)
    ((?:$|\s|[{re.escape(string.punctuation)}]).*)
    $
""", re.VERBOSE)


_ArgType: Final = type("ARG", (), {
    "__repr__": lambda _: "<ARG>",
    "__str__": lambda _: "*",
})
ARG: Final = _ArgType()

@dataclasses.dataclass
class FormatSpec:
    raw: str = dataclasses.field(repr=False)
    text: str
    type: str | None = None
    key: str | None = None
    index: int = 0
    flags: set[str] = dataclasses.field(default_factory=set)
    width: int | _ArgType | None = None
    precision: int | _ArgType | None = None
    size: str | None = None

    def as_format(self) -> str:
        return f"{self.text}{self.raw}"

    @property
    def value_is_arg(self) -> bool:
        return bool(self.type and not self.key)

    @property
    def width_is_arg(self) -> bool:
        return bool(self.type and self.width is ARG)

    @property
    def precision_is_arg(self) -> bool:
        return bool(self.type and self.precision is ARG)

    @property
    def argcount(self) -> int:
        return self.width_is_arg + self.precision_is_arg + self.value_is_arg

    @property
    def arg_index(self) -> int | None:
        return self.index + self.width_is_arg + self.precision_is_arg \
                if self.value_is_arg else None

    @property
    def width_index(self) -> int | None:
        return self.index \
                if self.width_is_arg else None

    @property
    def precision_index(self) -> int | None:
        return self.index + self.width_is_arg \
                if self.precision_is_arg else None



def _parse_percent_format(format: str) -> Iterator[FormatSpec]:
    def _parse_int(v: str | None) -> int | _ArgType | None:
        if v is None:
            return None
        elif v == "*":
            return ARG
        elif v.isdecimal():
            return int(v)
        else:
            return None

    p = 0
    c = 0
    while p < len(format):
        if (m := PERCENT_RE.search(format, pos=p)):
            gd = m.groupdict()
            yield (fs := FormatSpec(
                raw=format[m.start():m.end()],
                text=format[p:m.start()],
                type=gd["type"],
                key=gd["key"],
                index=c,
                flags=set(gd["flags"] or ""),
                width=_parse_int(gd["width"]),
                precision=_parse_int(gd["precision"]),
                size=gd["size"],
            ))
            c += fs.argcount
            p = m.end()
        else:
            yield FormatSpec(
                raw="",
                text=format[p:],
                index=c,
            )
            break

def _fix_percent_plurals(
    fmt: str,
    args: tuple[Any, ...] = (),
    kwargs: dict[str, Any] | None = None,
) -> str:
    last = None
    new = ""
    for spec in _parse_percent_format(fmt):
        if last:
            if (m := PLURAL_RE.match(spec.text)):
                pre, noun, post = m.groups()
                val = None
                if last.key is not None:
                    if kwargs:
                        val = kwargs.get(last.key)
                elif (i := last.arg_index) is not None and 0 <= i <= len(args):
                    val = args[i]
                if isinstance(val, int):
                    if val != 1:
                        noun = inflection.pluralize(noun)
                    spec.text = f"{pre}{noun}{post}"
        new += spec.as_format()
        last = spec
    return new


class StreamHandler(BaseStreamHandler):
    """
    Basic StreamHandler that ensures that the wrapped stream is flushed after
    any messages are emitted in order to work around supervisord being slow.
    """

    def emit(self, record: BaseLogRecord) -> None:
        super().emit(record)
        self.flush()


class FileHandler(BaseFileHandler):
    """
    Basic FileHandler that ensures that the opened file is flushed after
    any messages are emitted in order to work around people doing silly things
    and writing to /dev/stdout or /dev/stderr, etc.
    """

    def emit(self, record: BaseLogRecord) -> None:
        super().emit(record)
        self.flush()


class LogRecord(BaseLogRecord):
    """
    Enhanced log record with some extra, useful fields to provide concise,
    threading-/asyncio-aware information about where logging events occurred.
    Also levels as emoji because it's extra-short and we can?
    """

    levelicon: str
    shortlevel: str
    location: str
    workerName: str
    thisName: str

    def getMessage(self) -> str:
        msg = str(self.msg)
        if self.args:
            try:
                if isinstance(self.args, dict):
                    msg = _fix_percent_plurals(msg, (), self.args)
                elif isinstance(self.args, tuple):
                    msg = _fix_percent_plurals(msg, self.args)
            except:
                pass
            msg = msg % self.args
        return msg


def create_log_record(*args, **kwargs) -> LogRecord:
    """
    Create an enhanced log record; used as the log record factory.
    """
    # create a new logging record similarly to how it's normally created
    record = LogRecord(*args)
    for k, v in kwargs.items():
        setattr(record, k, v)
    # store our shorthand forms for the level name
    record.shortlevel, record.levelicon = _level_shorthand_mapping.get(
        record.levelno, _level_shorthand_mapping[None],
    )
    # store a shorthand location (so we can do column alignment)
    record.location = f"{record.filename}:{record.lineno}"
    # make sure we have a sane process name, including pulling supervisor info
    if SUPERVISOR_PROCESS_NAME:
        record.processName = SUPERVISOR_PROCESS_NAME
    elif record.processName == "MainProcess":
        record.processName = str(record.process)
    # figure out if we are in a thread/task and store that as a "worker" name
    worker = []
    if threading.main_thread().ident != record.thread:
        worker.append(record.threadName)
    if asyncio._get_running_loop() and record.taskName is not None:
        worker.append(record.taskName)
    record.workerName = ":".join(worker) if worker else DEFAULT_WORKER_NAME
    # store a simplified process/worker "name" as well
    record.thisName = "{}{}".format(
        record.processName,
        f"({record.workerName})" if worker else "",
    )
    return record


class Logger(BaseLogger):
    def trace(self, msg: str, *args, **kwargs) -> None:
        if self.isEnabledFor(TRACE):
            self._log(TRACE, msg, args, **kwargs)


class LoggerAdapter(BaseLoggerAdapter):
    def trace(self, msg: str, *args, **kwargs) -> None:
        if (fn := getattr(self.logger, "trace", None)):
            fn(msg, *args, **kwargs)
        else:
            if self.isEnabledFor(TRACE):
                self._log(TRACE, msg, args, **kwargs)


# turn on warning capturing so we get more consistent output
logging.captureWarnings(True)

# replace the log record factory with our own, enhanced one
logging.setLogRecordFactory(create_log_record)
# replace the log class with our own
logging.setLoggerClass(Logger)

# replace the root logger
root = LoggerAdapter(root)

# add an additional log level for super-extra-debugging info
TRACE: Final = 5
logging.addLevelName(TRACE, "TRACE")

# define our stock shorthands
_level_shorthand_mapping = {
    TRACE:      ("TRCE", "🪡"),
    DEBUG:      ("DBG",  "🪴"),
    INFO:       ("INFO", "💬"),
    WARNING:    ("WARN", "🚧"),
    ERROR:      ("ERR",  "🚨"),
    CRITICAL:   ("CRIT", "💥"),
    None:       ("????", "❓"),
}


def addLevelName(
    level: int,
    name: str,
    short: str = "???",
    icon: str = "❓",
) -> None:
    """
    Add a new level number-name mapping, while also adding a custom shorthand
    notation and/or emoji/icon for the enhanced log records.
    """
    logging.addLevelName(level, name)
    _level_shorthand_mapping[level] = (short, icon)


BASE_LOGLEVEL: Final = logging.WARNING
QUIET_LOGLEVEL: Final = logging.CRITICAL
DEFAULT_LOGLEVEL: Final = logging.INFO


def basicConfig(
    *,
    base_level: int = BASE_LOGLEVEL,
    datefmt: str = DEFAULT_DATEFMT,
    encoding: str | None = None,
    errors: str | None = None,
    filemode: str = "a",
    filename: str | pathlib.Path | os.PathLike | None = None,
    force: bool | None = None,
    format: str | None = None,
    handlers: list[BaseStreamHandler] | None = None,
    level: int = NOTSET,
    quiet: bool = False,
    quiet_level: int = QUIET_LOGLEVEL,
    stream: SupportsWrite[str] | None = None,
    style: logging._FormatStyle = "{",
    verbosity: int | None = None,
) -> None:
    """
    As `logging.basicConfig()`, but use some sane defaults for malcolm logging.
    """
    # if we weren't given an explicit level, figure out a sane value based on
    # the other verbosity-related arguments
    if level == NOTSET:
        if quiet:
            level = quiet_level
        elif verbosity is not None:
            all_levels = sorted(
                (
                    v for v in set(logging.getLevelNamesMapping().values())
                    if 0 < v <= base_level
                ),
                reverse=True,
            )
            level = all_levels[max(0, min(verbosity, len(all_levels)-1))]
        else:
            level = DEFAULT_LOGLEVEL
    # build default handlers if none were provided
    if handlers is None:
        if filename is not None:
            handlers = [
                FileHandler(
                    os.fspath(filename),
                    mode=filemode,
                    encoding=encoding,
                    errors=errors,
                ),
            ]
        else:
            handlers = [
                StreamHandler(stream),
            ]
    # determine our default format if one wasn't given
    if format is None:
        format = DEFAULT_FORMAT[style]
    # and then pass the required parameters on to the base function
    logging.basicConfig(
        level=level,
        style=style,
        format=format,
        datefmt=datefmt,
        handlers=handlers,
        force=force,
    )


def trace(msg: str, *args, stacklevel: int = 1, **kwargs) -> None:
    root.log(TRACE, msg, *args, stacklevel=stacklevel+1, **kwargs)


