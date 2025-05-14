#!/usr/bin/env python3

import json
import logging
import os
import socket
import time
import malcolm_utils
from typing import Optional, Dict, Any, Union


SuricataMaxRetriesDefault = 30


class SuricataSocketClient:
    """Client for communicating with Suricata's unix socket interface"""

    def __init__(
        self,
        socket_path: str = '/var/run/suricata/suricata-command.socket',
        logger: Optional[logging.Logger] = None,
        debug: bool = False,
        max_retries: int = SuricataMaxRetriesDefault,
        retry_delay: int = 1,
        process_pcap_wait_delay: int = 1,
        output_dir: str = '/var/log/suricata',
    ):
        self.socket_path = socket_path
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
                self.sock.send(handshake.encode('utf-8'))

                # Read response
                response = self.sock.recv(4096).decode('utf-8')
                self._debug(f"Handshake response: {response.strip()}")

                try:
                    handshake_json = json.loads(response)
                    if handshake_json.get("return") == "OK":
                        self._debug("Handshake successful")
                        return
                    else:
                        self._debug(f"ERROR: Unexpected handshake response: {handshake_json}")
                        raise ConnectionError(f"Handshake failed: {handshake_json}")
                except json.JSONDecodeError as e:
                    self._debug(f"ERROR: Failed to decode handshake response: {e}")
                    self._debug(f"ERROR: Raw response was: {repr(response)}")
                    raise ConnectionError(f"Failed to decode handshake response: {e}")

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

    def _send_command(
        self,
        command: Dict[str, Any],
        retries: int = 3,
    ) -> Union[Dict[str, Any], None]:
        """Send a command to Suricata socket and return the response"""
        attempts = 0
        while attempts < retries:
            try:
                # Convert command to JSON and send with newline
                command_json = json.dumps(command) + "\n"
                self._debug(f"\nSending command: {command_json.strip()}")
                self.sock.send(command_json.encode('utf-8'))

                # Read response
                response = self.sock.recv(4096).decode('utf-8')
                self._debug(f"Response received: {response.strip()}")

                if not response:
                    self._debug("ERROR: Empty response received")
                    return None

                try:
                    decoded_response = json.loads(response)
                    if decoded_response.get("return") == "NOK":
                        self._debug(f"ERROR: Command failed: {decoded_response}")
                        return None
                    return decoded_response
                except json.JSONDecodeError as e:
                    self._debug(f"ERROR: Failed to decode response: {e}")
                    self._debug(f"ERROR: Raw response was: {repr(response)}")
                    if attempts + 1 >= retries:
                        return None
                    attempts += 1
                    time.sleep(self.retry_delay)

            except socket.error as e:
                self._debug(f"ERROR: Socket error: {e}")
                if attempts + 1 >= retries:
                    return None
                attempts += 1
                time.sleep(self.retry_delay)
                self._connect()

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
                }
            )
            if not submit_response or submit_response.get("return") != "OK":
                self._debug(f"ERROR: Failed to process PCAP: {submit_response}")
                return False

            self._debug(f"Successfully queued PCAP: {pcap_file}")
            return True

        except Exception as e:
            self._debug(f"ERROR: Exception processing PCAP: {e}")
            return False

    def close(
        self,
    ) -> None:
        """Close the socket connection"""
        try:
            self.sock.close()
        except Exception:
            pass
