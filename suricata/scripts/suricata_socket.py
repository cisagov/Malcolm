#!/usr/bin/env python3

import codecs
import json
import logging
import os
import shutil
import socket
import tempfile
import threading
import time
import malcolm_utils
from typing import Optional, Dict, Any, Tuple, Union

SuricataMaxRetriesDefault = 30
SuricataQueueSizeError = 999
SuricataRuleReloadTimeoutDefault = int(os.getenv('SURICATA_SOCKET_RULE_RELOAD_TIMEOUT_SEC', '900'))
SuricataWarmUpTimeoutDefault = int(os.getenv('SURICATA_SOCKET_WARMUP_TIMEOUT_SEC', '60'))

# A minimal one-packet PCAP (a UDP datagram from 127.0.0.1 to 127.0.0.1:9) processed by a newly-started
#   socket-mode instance before its rules are reloaded. See _ensure_rules_reloaded for why.
SuricataWarmUpPcap = bytes.fromhex(
    'd4c3b2a1020004000000000000000000ffff000001000000000000000000000041000000410000000200000000020200'
    '000000010800450000330001400040113cb77f0000017f0000019c400009001f00006d616c636f6c6d2d73757269636174'
    '612d7761726d7570'
)


class SuricataSocketClient:
    """Client for communicating with Suricata's unix socket interface"""

    # Suricata instances whose rules have been reloaded since they started, keyed by socket path, with the
    #   socket file's (device, inode, ctime) to tell when the instance behind a path has restarted (Suricata
    #   recreates its socket on startup; ctime is included because a recreated socket can reuse the same
    #   inode number). Shared by every client in this process, so each instance is reloaded once no matter
    #   how many clients connect to it or how often they reconnect. See _ensure_rules_reloaded for why the reload
    #   is needed.
    _reloaded_instances: Dict[str, Tuple[int, int, int]] = {}
    _reloaded_instances_lock = threading.Lock()
    _json_decoder = json.JSONDecoder()

    def __init__(
        self,
        socket_path: str = '/var/run/suricata/suricata-command.socket',
        logger: Optional[logging.Logger] = None,
        debug: bool = False,
        max_retries: int = SuricataMaxRetriesDefault,
        retry_delay: int = 1,
        process_pcap_wait_delay: int = 1,
        output_dir: str = '/var/log/suricata',
        rule_reload_timeout: int = SuricataRuleReloadTimeoutDefault,
        warm_up_timeout: int = SuricataWarmUpTimeoutDefault,
    ):
        self.socket_path = socket_path
        self.rule_reload_timeout = rule_reload_timeout
        self.warm_up_timeout = warm_up_timeout
        self.logger = logger or logging.getLogger(__name__)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.process_pcap_wait_delay = process_pcap_wait_delay
        self.output_dir = output_dir
        self.debug_enabled = debug
        self.debug_log = os.path.join(self.output_dir, 'socket_debug.log')

        # Ensure log directory exists
        os.makedirs(os.path.dirname(self.debug_log), exist_ok=True)

        # Open debug log file
        if self.debug_enabled:
            try:
                with open(self.debug_log, 'a') as f:
                    f.write("\n\n=== New Session Started ===\n\n")
            except Exception as e:
                self.logger.error(f"Failed to write to debug log {self.debug_log}: {e}")

        self._connect()

    def _debug(
        self,
        msg: str,
    ) -> None:
        if not self.debug_enabled:
            return

        """Write a debug message to the log file and logger"""
        try:
            with open(self.debug_log, 'a') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
        except Exception as e:
            self.logger.debug(f"Failed to write to debug log: {e}")
        # Always log through logger as well
        self.logger.debug(msg)

    def _connect(
        self,
    ) -> None:
        """Establish connection to Suricata socket with retries"""
        attempts = 0
        last_error = None

        while attempts < self.max_retries:
            try:
                self._debug(f"Attempt {attempts + 1}: Connecting to socket at {self.socket_path}")
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(5)  # 5 second timeout
                self.sock.connect(self.socket_path)
                self._debug(f"Successfully connected to Suricata socket after {attempts+1} attempts")

                # Initial version handshake - this is a special case, not a command
                handshake = json.dumps({"version": "0.1"}) + "\n"
                self._debug(f"Sending handshake: {handshake.strip()}")
                self.sock.sendall(handshake.encode('utf-8'))

                # Read response
                handshake_json = self._recv_json()
                self._debug(f"Handshake response: {handshake_json}")
                if handshake_json.get("return") == "OK":
                    self._debug("Handshake successful")
                    self._ensure_rules_reloaded()
                    return
                else:
                    self._debug(f"ERROR: Unexpected handshake response: {handshake_json}")
                    raise ConnectionError(f"Handshake failed: {handshake_json}")

            except socket.error as e:
                last_error = e
                attempts += 1
                if attempts < self.max_retries:
                    self._debug(f"ERROR: Socket connection failed: {e}")
                    self._debug(f"Retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay)

        error_msg = f"Failed to connect after {self.max_retries} attempts: {last_error}"
        self._debug(f"ERROR: {error_msg}")
        raise ConnectionError(error_msg)

    def _recv_json(
        self,
        max_bytes: int = 16 * 1024 * 1024,
    ) -> Dict[str, Any]:
        """Read exactly one JSON object from the socket, however many recv() calls that takes.

        With protocol version 0.1, Suricata doesn't delimit its responses, so the only way to know a
        response is complete is that it parses. Failures raise ConnectionError (an OSError, like
        socket.error) because the stream can't be trusted afterwards and the caller should reconnect.
        """
        decoder = codecs.getincrementaldecoder('utf-8')()
        buffer = ""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError(f"Socket closed with incomplete response: {buffer!r}")
            try:
                buffer += decoder.decode(chunk)
            except UnicodeDecodeError as e:
                raise ConnectionError(f"Failed to decode response: {e}")
            try:
                obj, _ = self._json_decoder.raw_decode(buffer.lstrip())
            except json.JSONDecodeError as e:
                if len(buffer) > max_bytes:
                    raise ConnectionError(f"Response exceeded {max_bytes} bytes without parsing: {e}")
                continue
            if not isinstance(obj, dict):
                raise ConnectionError(f"Unexpected response: {obj!r}")
            return obj

    def _reconnect(
        self,
    ) -> None:
        try:
            if getattr(self, 'sock', None):
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        self._connect()

    def _send_command(
        self,
        command: Dict[str, Any],
        retries: int = 3,
        idempotent: bool = True,
    ) -> Union[Dict[str, Any], None]:
        """Send a command to Suricata socket and return the response

        A command that changes Suricata's state (e.g., pcap-file) should pass idempotent=False. Once such a
        command has been sent, it isn't sent again, because Suricata may have acted on it even if the
        response never arrived.
        """
        command_json = json.dumps(command) + "\n"
        attempts = 0
        while attempts < retries:
            sent = False
            try:
                self._debug(f"\nSending command: {command_json.strip()}")
                self.sock.sendall(command_json.encode('utf-8'))
                sent = True

                decoded_response = self._recv_json()
                self._debug(f"Response received: {decoded_response}")
                if decoded_response.get("return") == "NOK":
                    self._debug(f"ERROR: Command failed: {decoded_response}")
                    return None
                return decoded_response

            except socket.error as e:
                self._debug(f"ERROR: Socket error: {e}")
                attempts += 1
                if attempts >= retries:
                    return None
                time.sleep(self.retry_delay)
                self._reconnect()
                if sent and not idempotent:
                    self._debug(f"ERROR: Not resending non-idempotent command: {command_json.strip()}")
                    return None

        return None

    def process_pcap(
        self,
        pcap_file: str,
        output_dir: str,
    ) -> bool:
        """Submit a PCAP file to Suricata for processing"""
        try:
            self._debug(f"\nProcessing PCAP: {pcap_file}")

            # Create output directory if it doesn't exist
            try:
                os.makedirs(output_dir, exist_ok=True)
                self._debug(f"Created output directory: {output_dir}")
            except Exception as e:
                self._debug(f"ERROR: Failed to create output directory {output_dir}: {e}")
                return False
            eve_json_file = os.path.join(output_dir, "eve.json")

            submit_response = self._send_command(
                {
                    "command": "pcap-file",
                    "arguments": {
                        "filename": pcap_file,
                        "output-dir": output_dir,
                    },
                },
                idempotent=False,
            )
            if not submit_response or submit_response.get("return") != "OK":
                self._debug(f"ERROR: Failed to process PCAP: {submit_response}")
                return False

            self._debug(f"Successfully queued PCAP: {pcap_file}")
            return True

        except Exception as e:
            self._debug(f"ERROR: Exception processing PCAP: {e}")
            return False

    def _ensure_rules_reloaded(
        self,
    ) -> None:
        """Reload the rules of the connected Suricata instance if that hasn't been done since it started

        Called on every successful connection (initial or reconnect), holding a lock shared by all
        clients so other clients wait rather than submitting PCAP to an instance mid-reload.

        In unix-socket mode, Suricata only starts building rule metadata (alert.metadata in eve.json)
        once the alert output has been set up for a pcap-file run. Neither the rules loaded at
        startup nor a reload before the first run get it, so the instance first processes a tiny
        warm-up PCAP, and the rules are reloaded after that.
        """
        try:
            socket_stat = os.stat(self.socket_path)
            instance_id = (socket_stat.st_dev, socket_stat.st_ino, socket_stat.st_ctime_ns)
        except OSError as e:
            self._debug(f"ERROR: Could not stat {self.socket_path} to check rule reload: {e}")
            return

        socket_name = os.path.basename(self.socket_path)
        with SuricataSocketClient._reloaded_instances_lock:
            if SuricataSocketClient._reloaded_instances.get(self.socket_path) == instance_id:
                return
            self.logger.info(f"Warming up {socket_name} before reloading rules")
            if not self._warm_up(timeout=self.warm_up_timeout):
                self.logger.warning(
                    f"Failed to warm up {socket_name} before reloading rules, alert rule metadata may be missing"
                )
                return
            self.logger.info(f"Reloading rules for {socket_name}")
            if self.reload_rules(timeout=self.rule_reload_timeout):
                SuricataSocketClient._reloaded_instances[self.socket_path] = instance_id
                self.logger.info(f"Reloaded rules for {socket_name}")
            else:
                self.logger.warning(f"Failed to reload rules for {socket_name}, alert rule metadata may be missing")

    def _is_idle(
        self,
    ) -> bool:
        """True if the instance has no PCAP queued or in progress"""
        current_response = self._send_command({"command": "pcap-current"}, retries=1)
        queue_response = self._send_command({"command": "pcap-file-number"}, retries=1)
        if (not current_response) or (not queue_response):
            return False
        return (current_response.get("message") in (None, "", "None")) and (str(queue_response.get("message")) == "0")

    def _warm_up(
        self,
        timeout: int = SuricataWarmUpTimeoutDefault,
    ) -> bool:
        """Process a minimal PCAP so the instance's outputs are set up, waiting until it's idle again"""
        warm_up_dir = None
        try:
            warm_up_dir = tempfile.mkdtemp(prefix='suricata-warmup-')
            os.chmod(warm_up_dir, 0o755)
            warm_up_pcap = os.path.join(warm_up_dir, 'warmup.pcap')
            warm_up_output_dir = os.path.join(warm_up_dir, 'output')
            os.makedirs(warm_up_output_dir)
            with open(warm_up_pcap, 'wb') as f:
                f.write(SuricataWarmUpPcap)
            os.chmod(warm_up_pcap, 0o644)

            self._debug(f"Submitting warm-up PCAP {warm_up_pcap}")
            submit_response = self._send_command(
                {
                    "command": "pcap-file",
                    "arguments": {
                        "filename": warm_up_pcap,
                        "output-dir": warm_up_output_dir,
                    },
                },
                retries=1,
                idempotent=False,
            )
            if (not submit_response) or (submit_response.get("return") != "OK"):
                self._debug(f"ERROR: Failed to submit warm-up PCAP: {submit_response}")
                return False

            # wait for the warm-up PCAP to finish (two consecutive idle checks, so a run that hasn't
            #   started yet isn't mistaken for one that's done)
            deadline = time.time() + timeout
            idle_checks = 0
            while time.time() < deadline:
                time.sleep(0.5)
                idle_checks = (idle_checks + 1) if self._is_idle() else 0
                if idle_checks >= 2:
                    self._debug("Warm-up PCAP processed")
                    return True

            self._debug(f"ERROR: Warm-up PCAP not processed within {timeout}s")
            return False

        except Exception as e:
            self._debug(f"ERROR: Exception during warm-up: {e}")
            return False

        finally:
            if warm_up_dir:
                shutil.rmtree(warm_up_dir, ignore_errors=True)

    def reload_rules(
        self,
        timeout: int = 900,
    ) -> bool:
        """Reload the ruleset and wait for it to finish (blocking)

        Note that in unix-socket mode this only enables rule metadata if the instance has already
        processed a pcap-file run; see _ensure_rules_reloaded.
        """
        previous_timeout = self.sock.gettimeout()
        try:
            self._debug(f"Reloading rules (timeout {timeout}s)")
            self.sock.settimeout(timeout)
            submit_response = self._send_command({"command": "reload-rules"}, retries=1)
            if (not submit_response) or (submit_response.get("return") != "OK"):
                self._debug(f"ERROR: Failed to reload rules: {submit_response}")
                return False
            self._debug(f"Successfully reloaded rules: {submit_response}")
            return True

        except Exception as e:
            self._debug(f"ERROR: Exception reloading rules: {e}")
            return False

        finally:
            try:
                self.sock.settimeout(previous_timeout)
            except Exception:
                pass

    def queue_size(
        self,
    ) -> int:
        """Get pcap-file-number for the client"""
        try:
            submit_response = self._send_command({"command": "pcap-file-number"})
            if (
                (not submit_response)
                or (submit_response.get("return") != "OK")
                or (not str(submit_response.get("message")).isdigit())
            ):
                self._debug(f"ERROR: Failed to get queue size: {submit_response}")
                return SuricataQueueSizeError

            count = submit_response.get("message", SuricataQueueSizeError)
            self._debug(f"Successfully got queue size: {count}")
            return count

        except Exception as e:
            self._debug(f"ERROR: Exception getting queue size: {e}")
            return SuricataQueueSizeError

    def close(
        self,
    ) -> None:
        """Close the socket connection"""
        try:
            self.sock.close()
        except Exception:
            pass
