from __future__ import annotations

import atexit
import json
import os
import signal
import subprocess
from collections.abc import Callable, Iterable
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from threading import Event, Thread
from typing import Any

import requests
from yarl import URL


def is_port_available(port: int, local_host: str) -> bool:
    with socket(AF_INET, SOCK_STREAM) as s:
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        try:
            s.bind((local_host, port))
            return True
        except OSError:
            return False


default_tunnel_schemes: dict[str, int] = {
    "http": 80,
    "https": 443,
    "ssh": 22,
    "rdp": 3389,
    "tcp": 7864,
    "smb": 445,
}

default_proxy_schemes: dict[str, int] = {
    "ssh": 22,
    "rdp": 3389,
    "tcp": 7864,
    "smb": 445,
}


def find_available_port(
    ports: Iterable[int],
    local_host: str,
) -> int:
    for port in ports:
        if is_port_available(port, local_host):
            return port
    raise RuntimeError("no port is available")


class CloudflaredError(Exception):
    pass


class Log(dict):
    level: str
    message: str | None
    error: str | None

    def __init__(self, log: dict[str, Any]):
        super().__init__(log)
        self.setdefault("message", None)
        self.setdefault("error", None)

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key, value):
        self[key] = value


def output_handler(
    tunnel: QuickTunnel, log_handler: Callable[[QuickTunnel, Log]], stop: Event
):
    assert tunnel.process.stderr is not None

    for raw_log in tunnel.process.stderr:
        if stop.is_set():
            break
        try:
            log: dict[str, Any] = json.loads(raw_log)
        except json.JSONDecodeError:
            continue

        try:
            log_handler(tunnel, Log(log))
        except Exception:
            tunnel.close()
            raise


def wait_for_tunnel_registration(
    tunnel: QuickTunnel, log_handler: Callable[[QuickTunnel, Log]]
):
    skip_message_prefix = [
        f"Configuration file {'NUL' if os.name == 'nt' else '/dev/null'} was empty",
        "Thank you for trying Cloudflare Tunnel",
    ]
    log_number = -1

    log: dict[str, Any] = {}

    assert tunnel.process.stderr is not None

    for raw_log in tunnel.process.stderr:
        log_number += 1
        try:
            log = json.loads(raw_log)
        except json.JSONDecodeError:
            continue

        if log_number < len(skip_message_prefix) and log.get("message", "").startswith(
            skip_message_prefix[log_number]
        ):
            continue

        log_handler(tunnel, Log(log))

        if log.get("message") == "Registered tunnel connection":
            return

    raise CloudflaredError("Tunnel connection registration failed")


def get_hostname(metrics_local_origin: str) -> str:
    url = f"{metrics_local_origin}/quicktunnel"
    response = requests.get(url)
    data = response.json()
    return data["hostname"]


class QuickTunnel:
    @staticmethod
    def warn_log_handler(tunnel: QuickTunnel, log: Log):
        prefix = f"quick tunnel {log.level}:"
        if log.level != "info":
            if log.error:
                print(prefix, log.error)
            if log.message:
                print(prefix, log.message)

    @staticmethod
    def info_log_handler(tunnel: QuickTunnel, log: Log):
        prefix = f"quick tunnel {log.level}:"
        if log.error:
            print(prefix, log.error)
        if log.message:
            print(prefix, log.message)

    def __init__(
        self,
        local_url: URL,
        metrics_local_port: int | None = None,
        metrics_local_host: str = "localhost",
        log_handler: Callable[[QuickTunnel, Log]] = warn_log_handler,
        cloudflared_path: str = "cloudflared",
    ) -> None:
        if local_url.scheme not in default_tunnel_schemes:
            raise ValueError(
                f"Invalid or unsupported scheme [{local_url.scheme}] in local_url [{local_url}]"
            )

        if local_url.port is None:
            local_url = local_url.with_port(default_tunnel_schemes[local_url.scheme])

        self.local_url = local_url

        metrics_local_port = (
            find_available_port(range(20241, 20246), metrics_local_host)
            if metrics_local_port is None
            else metrics_local_port
        )

        metrics_socket_address = f"{metrics_local_host}:{metrics_local_port}"
        self.metrics_local_origin = f"http://{metrics_socket_address}"

        command = [
            cloudflared_path,
            "tunnel",
            "--url",
            str(local_url),
            "--metrics",
            metrics_socket_address,
            "--output",
            "json",
            "--config",
        ]

        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            command.append("NUL")
        else:
            kwargs["start_new_session"] = True
            command.append("/dev/null")

        self.process = subprocess.Popen(
            command,
            encoding="utf-8",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            **kwargs,
        )

        try:
            atexit.register(self.close)

            wait_for_tunnel_registration(self, log_handler)
            hostname = get_hostname(self.metrics_local_origin)
            self.id = hostname.split(".", 1)[0]
            self.origin = "https://" + hostname
            self.stop_logging_event = Event()
            self.output_handler_thread = Thread(
                target=output_handler,
                args=(self, log_handler, self.stop_logging_event),
            )
            self.output_handler_thread.start()
        except BaseException:
            self.close()
            raise

    def stop_logging(self):
        self.stop_logging_event.set()

    def is_online(self) -> bool:
        try:
            origin = f"{self.metrics_local_origin}/ready"
            response = requests.get(origin)
            data = response.json()

            return data["status"] == 200
        except requests.exceptions.RequestException:
            return False

    def is_process_running(self) -> bool:
        return self.process.poll() is None

    def is_process_closed(self) -> bool:
        return not self.is_process_running()

    def close(self):
        if self.is_process_closed():
            return
        if os.name == "nt":
            self.process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(self.process.pid, signal.SIGINT)
        atexit.unregister(self.close)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop_logging()
        self.close()

    def __str__(self):
        return f"Tunneling [{self.local_url}] -> [{self.origin}]"


def validate_websocket_listener(
    tunnel: TunnelProxy, log_handler: Callable[[TunnelProxy, Log]]
):
    log: dict[str, Any] = {}

    assert tunnel.process.stderr is not None

    raw_log = tunnel.process.stderr.readline()

    try:
        log = json.loads(raw_log)

        log_handler(tunnel, Log(log))

        if log.get("message") == "Start Websocket listener":
            return
    except json.JSONDecodeError:
        pass

    raise CloudflaredError("Failed to start websocket")


def access_output_handler(
    tunnel: TunnelProxy, log_handler: Callable[[TunnelProxy, Log]], stop: Event
):
    assert tunnel.process.stderr is not None

    for raw_log in tunnel.process.stderr:
        if stop.is_set():
            break
        try:
            log: dict[str, Any] = json.loads(raw_log)
        except json.JSONDecodeError:
            continue

        try:
            log_handler(tunnel, Log(log))
        except Exception:
            tunnel.close()
            raise


class TunnelProxy:
    @staticmethod
    def warn_log_handler(tunnel: TunnelProxy, log: Log):
        prefix = f"tunnel proxy {log.level}:"
        if log.level != "info":
            if log.error:
                print(prefix, log.error)
            if log.message:
                print(prefix, log.message)

    @staticmethod
    def info_log_handler(tunnel: TunnelProxy, log: Log):
        prefix = f"tunnel proxy {log.level}:"
        if log.error:
            print(prefix, log.error)
        if log.message:
            print(prefix, log.message)

    def __init__(
        self,
        tunnel_origin: str,
        local_port: int | None = None,
        local_host: str = "localhost",
        scheme: str = "tcp",
        log_handler: Callable[[TunnelProxy, Log]] = warn_log_handler,
        cloudflared_path: str = "cloudflared",
    ) -> None:
        self.local_port = (
            default_proxy_schemes[scheme] if local_port is None else local_port
        )
        self.local_host = local_host
        self.tunnel_origin = tunnel_origin
        self.id = tunnel_origin[8:].split(".", 1)[0]

        command = [
            cloudflared_path,
            "--output",
            "json",
            "access",
            scheme,
            "--hostname",
            tunnel_origin,
            "--url",
            f"{local_host}:{self.local_port}",
        ]

        kwargs = {}
        if os.name == "nt":  # windows
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True

        self.process = subprocess.Popen(
            command,
            encoding="utf-8",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            **kwargs,
        )

        try:
            atexit.register(self.close)

            validate_websocket_listener(self, log_handler)

            self.stop_logging_event = Event()
            self.output_handler_thread = Thread(
                target=access_output_handler,
                args=(self, log_handler, self.stop_logging_event),
            )
            self.output_handler_thread.start()
        except BaseException:
            self.close()
            raise

    def is_origin_online(
        self, read_timeout: float | None = 2, timeout: float | None = 5
    ) -> bool:
        try:
            response = requests.head(
                self.tunnel_origin, timeout=(timeout, read_timeout)
            )
        except requests.exceptions.ReadTimeout:
            return True
        except requests.exceptions.ConnectionError:
            return False
        except requests.exceptions.Timeout:
            return False

        return response.status_code != 530

    def stop_logging(self):
        self.stop_logging_event.set()

    def is_process_running(self) -> bool:
        return self.process.poll() is None

    def is_process_closed(self) -> bool:
        return not self.is_process_running()

    def close(self):
        if self.is_process_closed():
            return
        if os.name == "nt":
            self.process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(self.process.pid, signal.SIGINT)
        atexit.unregister(self.close)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __str__(self):
        return (
            f"Proxying [{self.tunnel_origin}] -> [{self.local_host}:{self.local_port}]"
        )
