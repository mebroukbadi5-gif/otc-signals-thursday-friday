#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import ssl
import json
import time
import math
import struct
import logging
import asyncio
import calendar
import platform
import random
import re
import shutil
import threading
import traceback
import itertools
import configparser
import contextlib
from pathlib import Path
from datetime import datetime, timedelta
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Awaitable, Callable, Dict, Generic, Hashable, List, Literal, Mapping, Optional, Tuple, TypeVar

import certifi
import requests
import websocket
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from bs4.element import AttributeValueList
from fake_useragent import UserAgent

try:
    import orjson as _orjson
    HAS_ORJSON = True
except ImportError:
    _orjson = None
    HAS_ORJSON = False

# ==============================================================================
# WEB SERVER IMPORTS (Flask-based live chart dashboard)
# ==============================================================================
try:
    from flask import Flask, request as flask_request, Response, jsonify
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

# ==============================================================================
# SECTION 1: LOGGING & SSL SETUP
# ==============================================================================
def _prepare_logging():
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.NullHandler())
    websocket_logger = logging.getLogger("websocket")
    websocket_logger.setLevel(logging.INFO)
    websocket_logger.addHandler(logging.NullHandler())

_prepare_logging()
logger = logging.getLogger(__name__)

cert_path = certifi.where()
os.environ['SSL_CERT_FILE'] = cert_path
os.environ['WEBSOCKET_CLIENT_CA_BUNDLE'] = cert_path
cacert = os.environ.get('WEBSOCKET_CLIENT_CA_BUNDLE')

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_context.load_verify_locations(cert_path)


# ==============================================================================
# SECTION 1.5: EVENT-DRIVEN WAIT PRIMITIVES (replaces asyncio.sleep polling)
# ==============================================================================
# pyquotex._api._waits — " " .
# polling timeout asyncio.sleep
# asyncio.Event .

async def wait_until(predicate: Callable[[], bool], *, timeout: float = 10.0,
                      poll_interval: float = 0.05) -> None:
    """ predicate() poll_interval True timeout.

 asyncio.TimeoutError . :
 while not condition:
 await asyncio.sleep(X)
 latency X poll_interval (50ms ).
 """
    async def _loop():
        while not predicate():
            await asyncio.sleep(poll_interval)
    await asyncio.wait_for(_loop(), timeout=timeout)


async def wait_for_first_event(*events: asyncio.Event, timeout: float = 10.0) -> int:
    """ event index. TimeoutError .

 :
 for _ in range(100):
 if cond_a: return A
 if cond_b: return B
 await asyncio.sleep(0.1)
 """
    if not events:
        raise ValueError("wait_for_first_event requires at least one event")
    tasks = [asyncio.ensure_future(e.wait()) for e in events]
    try:
        done, pending = await asyncio.wait(tasks, timeout=timeout,
                                           return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for i, t in enumerate(tasks):
            if t in done and t.result() and not t.cancelled():
                return i
        # timeout
        raise asyncio.TimeoutError()
    except asyncio.CancelledError:
        for t in tasks:
            if not t.done():
                t.cancel()
        raise


def _schedule_event_set(event: Optional[asyncio.Event],
                        loop: Optional[asyncio.AbstractEventLoop]) -> None:
    """ asyncio.Event thread ( websocket thread).

 run_coroutine_threadsafe coroutine 
 callback loop thread-safe loop.call_soon_threadsafe.
 """
    if event is None or loop is None:
        return
    try:
        if not loop.is_closed() and loop.is_running():
            loop.call_soon_threadsafe(event.set)
    except RuntimeError:
        # loop —
        pass


# ==============================================================================
# SECTION 2: CONSTANTS & SESSION
# ==============================================================================
USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
base_dir = Path.cwd()
session_lock = threading.Lock()

def resource_path(relative_path: str) -> Path:
    global base_dir
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base_dir = Path(sys._MEIPASS)
    return base_dir / relative_path

def load_session(email: str, user_agent: str = None) -> dict:
    if user_agent is None:
        try: user_agent = UserAgent().random
        except Exception: user_agent = USER_AGENT
    output_file = Path(resource_path("session.json"))
    with session_lock:
        all_sessions = {}
        if output_file.exists():
            try: all_sessions = json.loads(output_file.read_text())
            except json.JSONDecodeError: pass
        else:
            output_file.parent.mkdir(exist_ok=True, parents=True)
        if email not in all_sessions:
            all_sessions[email] = {"cookies": None, "token": None, "user_agent": user_agent}
        output_file.write_text(json.dumps(all_sessions, indent=4))
        return all_sessions.get(email)

def update_session(email: str, d: dict) -> dict:
    output_file = Path(resource_path("session.json"))
    with session_lock:
        current_sessions = {}
        if output_file.exists():
            try: current_sessions = json.loads(output_file.read_text())
            except json.JSONDecodeError: pass
        else:
            output_file.parent.mkdir(exist_ok=True, parents=True)
        current_sessions[email] = d
        output_file.write_text(json.dumps(current_sessions, indent=4))
        return current_sessions.get(email)

# ==============================================================================
# SECTION 3: HTTP NAVIGATOR (PROVEN WORKING METHOD)
# ==============================================================================
retry_strategy = Retry(
    total=3, backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504, 104],
    allowed_methods=["HEAD", "POST", "PUT", "GET", "OPTIONS"],
)

class CipherSuiteAdapter(HTTPAdapter):
    __attrs__ = ['ssl_context', 'max_retries', 'config', '_pool_connections', '_pool_maxsize', '_pool_block', 'source_address']
    def __init__(self, *args, **kwargs):
        self.ssl_context = kwargs.pop('ssl_context', None)
        self.cipherSuite = kwargs.pop('cipherSuite', 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.ecdhCurve = kwargs.pop('ecdhCurve', 'prime256v1')
        if not self.ssl_context:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.ssl_context.orig_wrap_socket = self.ssl_context.wrap_socket
            self.ssl_context.wrap_socket = self.wrap_socket
        if self.server_hostname:
            self.ssl_context.server_hostname = self.server_hostname
        if self.cipherSuite:
            self.ssl_context.set_ciphers(self.cipherSuite)
            self.ssl_context.set_ecdh_curve(self.ecdhCurve)
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        super().__init__(**kwargs)

    def wrap_socket(self, *args, **kwargs):
        if hasattr(self.ssl_context, 'server_hostname') and self.ssl_context.server_hostname:
            kwargs['server_hostname'] = self.ssl_context.server_hostname
            self.ssl_context.check_hostname = False
        else:
            self.ssl_context.check_hostname = True
        return self.ssl_context.orig_wrap_socket(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        kwargs['source_address'] = self.source_address
        return super().init_poolmanager(*args, **kwargs)

class Browser(Session):
    def __init__(self, *args, **kwargs):
        self.response = None
        self.default_headers = None
        self.ecdhCurve = kwargs.pop('ecdhCurve', 'prime256v1')
        self.cipherSuite = kwargs.pop('cipherSuite', 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.proxies = kwargs.pop('proxies', None)
        super().__init__(*args, **kwargs)
        self.headers.update(self.get_headers())
        self.mount('https://', CipherSuiteAdapter(ecdhCurve=self.ecdhCurve, cipherSuite=self.cipherSuite, server_hostname=self.server_hostname, source_address=self.source_address, ssl_context=ssl_context, max_retries=retry_strategy))

    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.close()
    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc_val, exc_tb): self.__exit__(exc_type, exc_val, exc_tb)

    def get_headers(self):
        self.default_headers = {"User-Agent": USER_AGENT}
        return self.default_headers

    def set_headers(self, headers=None):
        self.headers.update(self.default_headers)
        if headers: self.headers.update(headers)

    def get_cookies(self):
        return '; '.join(f'{i.name}={i.value}' for i in self.cookies)

    def get_soup(self):
        if self.response and not self.response.ok: raise RuntimeError(self.response.reason)
        return BeautifulSoup(self.response.content, "html.parser")

    def send_request(self, method, url, headers=None, **kwargs):
        merged_headers = self.headers.copy()
        if headers: merged_headers.update(headers)
        if self.proxies: kwargs['proxies'] = self.proxies
        self.response = self.request(method, url, headers=merged_headers, **kwargs)
        return self.response

# ==============================================================================
# SECTION 4: HTTP LOGIN & SETTINGS
# ==============================================================================
class Login(Browser):
    url = ""
    cookies = None
    ssid = None
    # FALLBACK default only - real value is set per-instance from api.host
    base_url = 'qxbroker.com'
    https_base_url = f'https://{base_url}'

    def __init__(self, api, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api = api
        # ---- DYNAMIC DOMAIN: follow the user-selected host -----------------
        # All HTTP login traffic now goes to the SAME domain that the WebSocket
        # will later connect to via ws2.<host>, so cookies/token stay valid.
        if not getattr(api, 'host', None):
            pass  # keep the hard-coded fallback
        else:
            self.base_url = api.host
            self.https_base_url = f'https://{self.base_url}'
        self.headers = self.get_headers()
        self.full_url = f"{self.https_base_url}/{api.lang}"

    def get_token(self):
        self.headers["Connection"] = "keep-alive"
        self.headers["Accept-Encoding"] = "gzip, deflate, br"
        self.headers["Accept-Language"] = "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3"
        self.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        self.headers["Referer"] = f"{self.full_url}/sign-in"
        self.headers["Upgrade-Insecure-Requests"] = "1"
        self.headers["Sec-Ch-Ua-Mobile"] = "?0"
        self.headers["Sec-Ch-Ua-Platform"] = '"Linux"'
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.headers["Sec-Fetch-User"] = "?1"
        self.headers["Sec-Fetch-Dest"] = "document"
        self.headers["Sec-Fetch-Mode"] = "navigate"
        self.headers["Dnt"] = "1"
        self.send_request("GET", f"{self.full_url}/sign-in/modal/")
        html = self.get_soup()
        match = html.find("input", {"name": "_token"})
        return None if not match else match.get("value")

    async def awaiting_pin(self, data, input_message):
        self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.headers["Referer"] = f"{self.full_url}/sign-in/modal"
        data["keep_code"] = 1
        try:
            code = input(input_message)
            if not code.isdigit():
                print("Please enter a valid code.")
                await self.awaiting_pin(data, input_message)
            data["code"] = code
        except KeyboardInterrupt:
            print("\nClosing program.")
            sys.exit()
        await asyncio.sleep(1)
        self.send_request(method="POST", url=f"{self.full_url}/sign-in/modal", data=data)

    def get_profile(self):
        self.response = self.send_request(method="GET", url=f"{self.full_url}/trade")
        if self.response:
            script = self.get_soup().find_all("script", {"type": "text/javascript"})
            script = script[0].get_text() if script else "{}"
            match = script.strip().replace(";", "").replace("window.settings = ", "")
            self.cookies = self.get_cookies()
            try:
                settings_dict = json.loads(match)
                self.ssid = settings_dict.get("token")
            except json.JSONDecodeError:
                self.ssid = None
            self.api.session_data["cookies"] = self.cookies
            self.api.session_data["token"] = self.ssid
            self.api.session_data["user_agent"] = self.headers["User-Agent"]
            update_session(self.api.username, self.api.session_data)
            return self.response, settings_dict if self.ssid else None
        return None, None

    async def _post(self, data):
        self.response = self.send_request(method="POST", url=f"{self.full_url}/sign-in/", data=data)
        required_keep_code = self.get_soup().find("input", {"name": "keep_code"})
        if required_keep_code:
            auth_body = self.get_soup().find("main", {"class": "auth__body"})
            input_message = f'{auth_body.find("p").text}: ' if auth_body.find("p") else "Enter the PIN code sent to your email: "
            await self.awaiting_pin(data, input_message)
            await asyncio.sleep(1)
            return self.success_login()
        return self.success_login()

    def success_login(self):
        if "trade" in str(self.response.url):
            return True, "Login successful."
        soup = self.get_soup()
        not_available = soup.select_one("#tab-1 > div > div.modal-sign__not-avalible__title")
        if not_available: return False, f"Service unavailable: {not_available.get_text(strip=True)}"
        error = soup.select_one("#tab-1 form > div:nth-child(2) > div")
        msg = error.get_text(strip=True) if error else "Unknown error"
        return False, f"Login failed. {msg}"

    async def __call__(self, username, password, user_data_dir=None):
        data = {"_token": self.get_token(), "email": username, "password": password, "remember": 1}
        status, msg = await self._post(data)
        if status: self.get_profile()
        return status, msg

class Settings(Browser):
    def __init__(self, api):
        super().__init__()
        self.set_headers()
        self.api = api
        self.headers = self.get_headers()

    def get_settings(self):
        self.headers["content-type"] = "application/json"
        self.headers["referer"] = f"{self.api.https_url}/{self.api.lang}/trade"
        self.headers["cookie"] = self.api.session_data.get("cookies", "")
        self.headers["user-agent"] = self.api.session_data.get("user_agent", "")
        response = self.send_request("GET", f"{self.api.https_url}/api/v1/cabinets/digest")
        return response.json()

# ==============================================================================
# SECTION 5: WEBSOCKET CLIENT & STATE (SYNC + EVENT REGISTRY INTEGRATION)
# ==============================================================================
class WebsocketStatus(IntEnum):
    DISCONNECTED = 0
    CONNECTED = 1
    CONNECTING = 2
    ERROR = -1

class AuthStatus(IntEnum):
    NOT_AUTHENTICATED = 0
    AUTHENTICATING = 1
    AUTHENTICATED = 2
    FAILED = -1

class ConnectionState:
    def __init__(self):
        self.SSID = None
        self.status = WebsocketStatus.DISCONNECTED
        self.auth_status = AuthStatus.NOT_AUTHENTICATED
        self.ssl_Mutual_exclusion = False
        self.ssl_Mutual_exclusion_write = False
        self.check_rejected_connection = False
        self.check_accepted_connection = False
        self.check_websocket_if_error = False
        self.check_websocket_if_connect = None
        self.websocket_error_reason = None

        # ===== EVENT-DRIVEN ADDITIONS =====
        # asyncio polling. lazily async context
        # init_events() "no running event loop" .
        self.ws_connected_event: Optional[asyncio.Event] = None
        self.ws_closed_event: Optional[asyncio.Event] = None
        self.auth_accepted_event: Optional[asyncio.Event] = None
        self.auth_rejected_event: Optional[asyncio.Event] = None
        self.ws_error_event: Optional[asyncio.Event] = None
        # loop websocket thread
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def init_events(self) -> None:
        """ loop . async context."""
        if self.ws_connected_event is None:
            self.ws_connected_event = asyncio.Event()
        if self.ws_closed_event is None:
            self.ws_closed_event = asyncio.Event()
        if self.auth_accepted_event is None:
            self.auth_accepted_event = asyncio.Event()
        if self.auth_rejected_event is None:
            self.auth_rejected_event = asyncio.Event()
        if self.ws_error_event is None:
            self.ws_error_event = asyncio.Event()
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None

    def reset_events(self) -> None:
        """ ."""
        for ev in (self.ws_connected_event, self.ws_closed_event,
                   self.auth_accepted_event, self.auth_rejected_event,
                   self.ws_error_event):
            if ev is not None:
                ev.clear()

    # wrappers thread (websocket thread)
    def signal_ws_connected(self) -> None:
        _schedule_event_set(self.ws_connected_event, self._loop)

    def signal_ws_closed(self) -> None:
        _schedule_event_set(self.ws_closed_event, self._loop)

    def signal_auth_accepted(self) -> None:
        _schedule_event_set(self.auth_accepted_event, self._loop)

    def signal_auth_rejected(self) -> None:
        _schedule_event_set(self.auth_rejected_event, self._loop)

    def signal_ws_error(self) -> None:
        _schedule_event_set(self.ws_error_event, self._loop)

class WebsocketClient:
    def __init__(self, api):
        self.api = api
        self.state = api.state
        self.headers = {
            "User-Agent": self.api.session_data.get("user_agent", USER_AGENT),
            "Origin": self.api.https_url,
            "Host": f"ws2.{self.api.host}",
        }
        self.wss = websocket.WebSocketApp(
            self.api.wss_url,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            on_open=self.on_open,
            on_ping=self.on_ping,
            on_pong=self.on_pong,
            header=self.headers,
            cookie=self.api.session_data.get("cookies"),
        )

    def on_message(self, wss, msg):
        self.state.ssl_Mutual_exclusion = True
        # ===== STALE-WATCHDOG: =====
        # watchdog .
        try:
            if self.api is not None:
                self.api.last_message_at = time.time()
        except Exception:
            pass
        try:
            msg_str = msg.decode("utf-8", errors="ignore") if isinstance(msg, bytes) else str(msg)

            if msg_str == "2":
                try:
                    self.wss.send("3")
                except Exception:
                    pass
                self.state.ssl_Mutual_exclusion = False
                return
            if msg_str == "3":
                self.state.ssl_Mutual_exclusion = False
                return

            if "authorization/reject" in msg_str:
                logger.warning("Token rejected.")
                self.state.check_rejected_connection = True
                self.state.auth_status = AuthStatus.FAILED
                # ===== EVENT-DRIVEN FIX =====
                self.state.signal_auth_rejected()
            elif "s_authorization" in msg_str:
                self.state.check_accepted_connection = True
                self.state.check_rejected_connection = False
                self.state.auth_status = AuthStatus.AUTHENTICATED
                self.state.status = WebsocketStatus.CONNECTED
                print("\n" + "="*60)
                print("Connected to server successfully")
                print("="*60 + "\n")
                # ===== EVENT-DRIVEN FIX =====
                self.state.signal_auth_accepted()

            message = None
            if len(msg_str) > 1 and msg_str[1] in ('[', '{'):
                try:
                    message = json.loads(msg_str[1:])
                except Exception:
                    pass

            if message is not None:
                self._process_message_and_raise_events(message)

            if str(msg_str) == "41":
                self.state.check_websocket_if_connect = 0
        except Exception as e:
            logger.error("Unhandled error in on_message: %s", e)
        self.state.ssl_Mutual_exclusion = False

    def _process_message_and_raise_events(self, message):
        try:
            loop = self.api._async_loop
            if loop is None or not loop.is_running():
                return

            if isinstance(message, dict):
                asset = message.get("asset")
                if asset and (message.get("candles") or message.get("data") or message.get("history")):
                    self.api.candle_v2_data[asset] = message
                    self.api.candles.candles_data = message.get("candles") or message.get("data") or message.get("history")

                    asyncio.run_coroutine_threadsafe(
                        self.api.event_registry.set_event(f'candles_ready_{asset}', message),
                        loop
                    )

                    index = message.get("index")
                    if index is not None:
                        asyncio.run_coroutine_threadsafe(
                            self.api.event_registry.set_event(f'candles_ready_{asset}_{index}', message),
                            loop
                        )

            if isinstance(message, dict) and (message.get("liveBalance") or message.get("demoBalance")):
                self.api.account_balance = message

            if isinstance(message, list) and len(message) > 0 and isinstance(message[0], list) and len(message[0]) == 4:
                asset = message[0][0]
                self.api.realtime_candles[asset] = message[0]
        except Exception as e:
            logger.debug(f"Error processing message: {e}")

    def on_error(self, wss, error):
        global CONNECTION_ALIVE
        logger.error(error)
        self.state.websocket_error_reason = str(error)
        self.state.check_websocket_if_error = True
        self.state.status = WebsocketStatus.ERROR
        self.state.check_accepted_connection = False
        # ===== EVENT-DRIVEN FIX =====
        self.state.signal_ws_error()
        try:
            CONNECTION_ALIVE = False
        except Exception:
            pass

    def on_open(self, wss):
        logger.info("Websocket client connected.")
        self.state.check_websocket_if_connect = 1
        self.state.status = WebsocketStatus.CONNECTED
        # ===== EVENT-DRIVEN FIX =====
        self.state.signal_ws_connected()
        asset_name = self.api.current_asset or "EURUSD"
        period = self.api.current_period or 60
        self.wss.send('42["tick"]')
        self.wss.send('42["indicator/list"]')
        self.wss.send('42["drawing/load"]')
        self.wss.send('42["pending/list"]')
        self.wss.send(f'42["instruments/update",{{"asset":"{asset_name}","period":{period}}}]')
        self.wss.send(f'42["depth/follow","{asset_name}"]')
        self.wss.send('42["chart_notification/get"]')
        self.wss.send('42["instruments/get"]')
        self.wss.send('42["tick"]')

    def on_close(self, wss, close_status_code, close_msg):
        global CONNECTION_ALIVE
        logger.info("Websocket connection closed.")
        self.state.check_websocket_if_connect = 0
        self.state.status = WebsocketStatus.DISCONNECTED
        self.state.check_accepted_connection = False
        # ===== EVENT-DRIVEN FIX =====
        self.state.signal_ws_closed()
        try:
            CONNECTION_ALIVE = False
        except Exception:
            pass

    def on_ping(self, wss, ping_msg): pass
    def on_pong(self, wss, pong_msg): pass

# ==============================================================================
# SECTION 6: QUOTEX API CORE
# ==============================================================================
class CandlesObj:
    def __init__(self): self.__candles_data = None
    @property
    def candles_data(self): return self.__candles_data
    @candles_data.setter
    def candles_data(self, candles_data): self.__candles_data = candles_data

class EventRegistry:
    def __init__(self):
        self._events: Dict[str, asyncio.Event] = {}
        self._data: Dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def get_event(self, key: str) -> asyncio.Event:
        async with self._lock:
            if key not in self._events:
                self._events[key] = asyncio.Event()
            return self._events[key]

    async def set_event(self, key: str, data: Any = None):
        async with self._lock:
            if key not in self._events:
                self._events[key] = asyncio.Event()
            self._data[key] = data
            self._events[key].set()

    async def wait_event(self, key: str, timeout: float = 30.0) -> Any:
        event = await self.get_event(key)
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return self._data.get(key)
        except asyncio.TimeoutError:
            return None

    async def clear_event(self, key: str):
        async with self._lock:
            if key in self._events:
                self._events[key].clear()
            if key in self._data:
                del self._data[key]

class QuotexAPI:
    def __init__(self, host, username, password, lang, proxies=None, user_data_dir="."):
        self.state = ConnectionState()
        self.trace_ws = False
        self.current_asset = None
        self.current_period = None
        self.account_balance = None
        self.account_type = 1
        self.instruments = None
        self.host = host
        self.https_url = f"https://{host}"
        self.wss_url = f"wss://ws2.{host}/socket.io/?EIO=3&transport=websocket"
        self.websocket_thread = None
        self.websocket_client = None
        self.username = username
        self.password = password
        self.proxies = proxies
        self.lang = lang
        self.user_data_dir = user_data_dir
        self.session_data = {}
        self.browser = Browser()
        self.browser.set_headers()
        self.settings = Settings(self)
        self.candles = CandlesObj()
        self.candle_v2_data = {}
        self.realtime_price = defaultdict(list)
        self.realtime_candles = {}
        self.event_registry = EventRegistry()
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None
        self._temp_status = ""
        # ===== STALE-WATCHDOG ADDITION =====
        # WS . watchdog
        # .
        self.last_message_at: float = time.time()
        # ===== FIX 7: Rate Limiter ( ) =====
        # . rate limiter
        # keepalive + watchdog.
        # rate limiter (15ms = ~66 req/s) bursts .
        self._ws_send_times: list[float] = []
        self._ws_min_interval: float = 0.015  # 15ms ( )
        self._ws_max_per_window: int = 100    # 100 / ()
        self._ws_window: float = 1.0          # 1
        self._throttle_multiplier: float = 1.0  # = 1.0 ( auto-throttle)
        self._last_send_at: float = 0.0

    @property
    def login(self): return Login(self)

    def _apply_rate_limit(self) -> None:
        """ rate limiting WS — .

 - (_ws_min_interval * _throttle_multiplier)
 - (_ws_max_per_window / _throttle_multiplier)
 """
        now = time.time()
        # 1)
        min_interval = self._ws_min_interval * self._throttle_multiplier
        if self._last_send_at > 0:
            elapsed = now - self._last_send_at
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
                now = time.time()
        # 2)
        window_size = self._ws_window * self._throttle_multiplier
        cutoff = now - window_size
        self._ws_send_times = [t for t in self._ws_send_times if t >= cutoff]
        # 3)
        if len(self._ws_send_times) >= self._ws_max_per_window:

            sleep_for = (self._ws_send_times[0] + window_size) - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.time()
                cutoff = now - window_size
                self._ws_send_times = [t for t in self._ws_send_times if t >= cutoff]
        # 4)
        self._ws_send_times.append(now)
        self._last_send_at = now

    def increase_throttle(self, factor: float = 2.0, max_multiplier: float = 8.0) -> None:
        """ ( ).
 => => => .
 """
        new_multiplier = min(self._throttle_multiplier * factor, max_multiplier)
        if new_multiplier != self._throttle_multiplier:
            self._throttle_multiplier = new_multiplier
            logger.info(f" Throttle increased to {new_multiplier}x (rate limit stress)")

    def decrease_throttle(self, factor: float = 0.5, min_multiplier: float = 1.0) -> None:
        """ ( )."""
        new_multiplier = max(self._throttle_multiplier * factor, min_multiplier)
        if new_multiplier != self._throttle_multiplier:
            self._throttle_multiplier = new_multiplier
            logger.info(f" Throttle restored to {new_multiplier}x")

    def send_websocket_request(self, data, no_force_send=True):
        # ===== FIX: busy-wait -> sleep + try/finally =====
        if no_force_send:
            deadline = time.time() + 5.0  # 5s
            while (self.state.ssl_Mutual_exclusion or self.state.ssl_Mutual_exclusion_write):
                if time.time() > deadline:
                    # — . .
                    break
                time.sleep(0.001)  # `pass` — CPU
        # ===== FIX 6: rate limit =====
        # : heartbeat messages ("2" "42[\"tick\"]" "42[\"instruments/get\"]")
        # rate limit — keepalive.
        is_heartbeat = (
            data == "2" or
            data == '42["tick"]' or
            data == '42["instruments/get"]' or
            'pending/list' in data or
            'indicator/list' in data or
            'drawing/load' in data
        )
        if not is_heartbeat:
            try:
                self._apply_rate_limit()
            except Exception:
                # rate limiter
                pass
        self.state.ssl_Mutual_exclusion_write = True
        try:
            if self.websocket_client and self.websocket_client.wss:
                self.websocket_client.wss.send(data)
        finally:
            # ===== FIX: flag =====
            self.state.ssl_Mutual_exclusion_write = False

    def subscribe_realtime_candle(self, asset, period):
        self.realtime_price[asset] = []
        self.realtime_candles[asset] = {}
        data = f'42["instruments/update", {json.dumps({"asset": asset, "period": period})}]'
        return self.send_websocket_request(data)

    def follow_candle(self, asset):
        return self.send_websocket_request(f'42["depth/follow", {json.dumps(asset)}]')

    def chart_notification(self, asset):
        return self.send_websocket_request(f'42["chart_notification/get", {json.dumps({"asset": asset, "version": "1.0.0"})}]')

    def get_candles_ws(self, asset, index, time_val, offset, period):
        payload = {"asset": asset, "index": index, "time": time_val, "offset": offset, "period": period}
        data = f'42["history/load",{json.dumps(payload)}]'
        return self.send_websocket_request(data)

    async def authenticate(self):
        async with self.login as login:
            status, msg = await login(self.username, self.password, self.user_data_dir)
        if status:
            self.state.SSID = self.session_data.get("token")
        return status, msg

    async def start_websocket(self):
        self.state.check_websocket_if_connect = None
        self.state.check_websocket_if_error = False
        self.state.websocket_error_reason = None
        # ===== EVENT-DRIVEN FIX =====
        # +
        self.state.init_events()
        self.state.reset_events()
        # loop ( reconnect)
        try:
            self.state._loop = asyncio.get_running_loop()
        except RuntimeError:
            self.state._loop = None

        if not self.state.SSID:
            await self.authenticate()
        self.websocket_client = WebsocketClient(self)
        payload = {
            "suppress_origin": True, "ping_interval": 24, "ping_timeout": 20, "ping_payload": "2",
            "origin": self.https_url, "host": f"ws2.{self.host}",
            "sslopt": {"check_hostname": True, "cert_reqs": ssl.CERT_REQUIRED, "ca_certs": cacert, "context": ssl_context},
        }
        if platform.system() == "Linux":
            payload["sslopt"]["ssl_version"] = ssl.PROTOCOL_TLS
        self.websocket_thread = threading.Thread(target=self.websocket_client.wss.run_forever, kwargs=payload)
        self.websocket_thread.daemon = True
        self.websocket_thread.start()

        # ===== EVENT-DRIVEN FIX =====
        # polling:
        # for _ in range(100):
        # if self.state.check_websocket_if_error: return False, ...
        # elif self.state.check_websocket_if_connect == 1: return True, ...
        # elif self.state.check_rejected_connection: return False, "Token Rejected."
        # await asyncio.sleep(0.1)
        # : connected, rejected, error, closed
        try:
            idx = await wait_for_first_event(
                self.state.ws_connected_event,
                self.state.auth_rejected_event,
                self.state.ws_error_event,
                self.state.ws_closed_event,
                timeout=10.0,
            )
        except asyncio.TimeoutError:
            return False, "Timeout waiting for websocket open"

        if idx == 0:
            return True, "Websocket connected successfully!!!"
        elif idx == 1:
            self.state.SSID = None
            return False, "Websocket Token Rejected."
        elif idx == 2:
            return False, self.state.websocket_error_reason or "Websocket error"
        elif idx == 3:
            return False, "Websocket connection closed."
        return False, "Unknown websocket state"

    async def send_ssid(self, timeout=10):
        if not self.state.SSID: return False
        # ===== EVENT-DRIVEN FIX =====
        # ( send_ssid start_websocket )
        if self.state.auth_accepted_event is None:
            self.state.init_events()
        self.state.auth_accepted_event.clear()
        self.state.auth_rejected_event.clear()

        payload = {"session": self.state.SSID, "isDemo": self.account_type, "tournamentId": 0}
        data = f'42["authorization",{json.dumps(payload)}]'
        self.send_websocket_request(data)

        # ===== EVENT-DRIVEN FIX =====
        # polling:
        # while not check_accepted and not check_rejected:
        # if time.time() - start_time > timeout: return False
        # await asyncio.sleep(0.5)
        # accepted rejected .
        try:
            idx = await wait_for_first_event(
                self.state.auth_accepted_event,
                self.state.auth_rejected_event,
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return False
        return idx == 0  # True accepted, False rejected

    async def connect(self, is_demo):
        self.account_type = 1 if is_demo else 0
        self.state.ssl_Mutual_exclusion = False
        self.state.ssl_Mutual_exclusion_write = False
        check_websocket, websocket_reason = await self.start_websocket()
        if not check_websocket: return check_websocket, websocket_reason
        check_ssid = await self.send_ssid()
        if not check_ssid:
            await self.authenticate()
            if self.state.SSID: await self.send_ssid()
        return check_websocket, websocket_reason

    async def close(self):
        if self.websocket_client and self.websocket_client.wss:
            self.websocket_client.wss.close()
            await asyncio.sleep(1)
        if self.websocket_thread and self.websocket_thread.is_alive():
            self.websocket_thread.join(timeout=5)
        return True

# ==============================================================================
# SECTION 7: QUOTEX STABLE API WITH FULL HISTORY MIXIN
# ==============================================================================
_request_counter = itertools.count(int(time.time() * 1000))

def group_by_period(data, period):
    grouped = defaultdict(list)
    for tick in data:
        timestamp = int(tick[0])
        timeframe = int(timestamp // period)
        grouped[timeframe].append(tick)
    return dict(grouped)

def calculate_candles(history, period):
    if not isinstance(history, list) or not history: return []
    grouped = group_by_period(history, period)
    candles = []
    for minute, ticks in grouped.items():
        open_price = ticks[0][1]
        close_price = ticks[-1][1]
        high_price = max(tick[1] for tick in ticks)
        low_price = min(tick[1] for tick in ticks)
        candle = {'time': minute * period, 'open': open_price, 'close': close_price, 'high': high_price, 'low': low_price, 'ticks': len(ticks)}
        candles.append(candle)
    return candles[:-1] if len(candles) > 1 else candles


# ===== FIX A: =====
# : calculate_candles "tick" [time, price]
# tick[1] open/high/low/close. Quotex
# "history/load" [time, open, close, high, low] (5 ).
# calculate_candles tick :
# open = high = low = close = open_price => !
# fill_gap_once => get_candles => prepare_candles.
# .
def _parse_raw_candles(raw_candles):
    """ WebSocket dicts OHLC .

 "history/load":
 1) [time, open, close, high, low] — Quotex (5 )
 2) [time, open, close, high, low, vol] — volume (6 )
 3) {"time", "open", "high", "low", "close", ...} — dict
 4) [time, price(, volume)] — tick ( )
 """
    if not raw_candles: return []
    parsed = []
    for c in raw_candles:
        try:
            if isinstance(c, dict) and 'time' in c:
                t = int(c.get('time', c.get('timestamp', 0)))
                o = float(c.get('open', 0) or 0)
                h = float(c.get('high', c.get('max', 0)) or 0)
                l = float(c.get('low', c.get('min', 0)) or 0)
                cl = float(c.get('close', c.get('c', 0)) or 0)
                v = int(c.get('volume', c.get('vol', 0)) or 0)
                if t > 0 and o > 0 and h > 0 and l > 0 and cl > 0:
                    parsed.append({'time': t, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': v})
            elif isinstance(c, (list, tuple)) and len(c) >= 5:
                # Quotex WS: [time, open, close, high, low(, volume)]
                t = int(c[0])
                o = float(c[1])
                cl = float(c[2])
                h = float(c[3])
                l = float(c[4])
                v = int(c[5]) if len(c) >= 6 else 0
                if t > 0 and o > 0 and h > 0 and l > 0 and cl > 0:
                    parsed.append({'time': t, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': v})
            elif isinstance(c, (list, tuple)) and len(c) >= 2:
                # tick format: [time, price(, volume)]
                t = int(c[0])
                p = float(c[1])
                v = int(c[2]) if len(c) >= 3 else 0
                if t > 0 and p > 0:
                    parsed.append({'time': t, 'open': p, 'high': p, 'low': p, 'close': p, 'volume': v})
        except (TypeError, ValueError):
            continue
    return parsed

def process_candles_v2(history, asset, data):
    if not history or not isinstance(history, dict): return data if data else []
    candles_data = history.get(asset, {})
    candles = candles_data.get("candles", [])[1:] if candles_data else []
    combined = candles + (data if data else [])
    if combined:
        candle_dict = {c.get('time'): c for c in combined if isinstance(c, dict) and 'time' in c}
        return list(candle_dict.values()) if candle_dict else []
    return combined

def merge_candles(candles_data):
    if not candles_data: return []
    candle_dict = {c['time']: c for c in candles_data if isinstance(c, dict) and 'time' in c}
    return sorted(candle_dict.values(), key=lambda x: x['time']) if candle_dict else []

class Quotex:
    def __init__(self, email=None, password=None, host="qxbroker.com", lang="en", proxies=None, user_data_dir="browser", asset_default="EURUSD", period_default=60):
        self.email = email
        self.password = password
        self.host = host
        self.lang = lang
        self.proxies = proxies
        self.user_data_dir = user_data_dir
        self.asset_default = asset_default
        self.period_default = period_default
        self.account_is_demo = 1
        self.codes_asset = {}
        self.api = None
        self.subscribe_candle = []
        self.subscribe_candle_all_size = []
        self.subscribe_mood = []
        session = load_session(self.email, USER_AGENT)
        self.session_data = session

    async def check_connect(self):
        if self.api is None: return False
        # ===== EVENT-DRIVEN FIX =====
        # :
        # await asyncio.sleep(1)
        # return self.api.state.check_accepted_connection == 1
        # . 2s 50ms
        # — latency 1000ms <100ms.
        try:
            await wait_until(
                lambda: self.api.state.check_accepted_connection == 1,
                timeout=2.0,
                poll_interval=0.05,
            )
            return True
        except asyncio.TimeoutError:
            return self.api.state.check_accepted_connection == 1

    async def connect(self):
        self.api = QuotexAPI(self.host, self.email, self.password, self.lang, proxies=self.proxies, user_data_dir=self.user_data_dir)
        self.api.session_data = self.session_data
        self.api.state.SSID = self.session_data.get("token")
        self.api._async_loop = asyncio.get_running_loop()
        if not self.session_data.get("token"):
            check, reason = await self.api.authenticate()
            if not check: return check, reason
        check, reason = await self.api.connect(self.account_is_demo == 1)
        if not check:
            self.session_data = {}
            return False, "Websocket connection rejected."
        return check, reason

    async def change_account(self, balance_mode: str):
        self.account_is_demo = 0 if balance_mode.upper() == "REAL" else 1
        self.api.account_type = self.account_is_demo
        payload = {"demo": self.api.account_type, "tournamentId": 0}
        self.api.send_websocket_request(f'42["account/change",{json.dumps(payload)}]')

    async def get_all_assets(self):
        return {}

    async def start_candles_stream(self, asset="EURUSD", period=60):
        if self.api:
            self.api.current_asset = asset
            self.api.current_period = period
            self.api.subscribe_realtime_candle(asset, period)
            self.api.chart_notification(asset)
            self.api.follow_candle(asset)

    async def get_realtime_candles(self, asset: str):
        if self.api: return self.api.realtime_candles.get(asset, [])
        return []

    async def get_candles(self, asset, end_from_time, offset, period, progressive=False, timeout=30, use_cache=False):
        if self.api is None: return None
        if end_from_time is None: end_from_time = time.time()
        index = calendar.timegm(time.gmtime())
        self.api.candles.candles_data = None
        await self.api.event_registry.clear_event(f'candles_ready_{asset}')
        await self.start_candles_stream(asset, period)
        self.api.get_candles_ws(asset, index, int(end_from_time), offset, period)
        try:
            history_data = await self.api.event_registry.wait_event(f'candles_ready_{asset}', timeout=timeout)
        except Exception:
            return None
        if history_data is None: return None
        candles = self.prepare_candles(asset, period, history_data)
        if progressive: return self.api.historical_candles.get("data", {})
        return candles

    async def _fetch_historical_batch(self, asset, fetch_time, offset, period, index, timeout):
        if self.api is None: return None
        payload = {"asset": asset, "index": index, "time": fetch_time, "offset": offset, "period": period}
        ws_msg = f'42["history/load",{json.dumps(payload)}]'
        event_name = f'candles_ready_{asset}_{index}'
        await self.api.event_registry.clear_event(event_name)
        self.api.send_websocket_request(ws_msg)
        try:
            return await self.api.event_registry.wait_event(event_name, timeout=timeout)
        except Exception:
            return None

    def _parse_historical_candles(self, raw_data):
        if raw_data is None: return []
        raw_candles = raw_data.get("data", []) or raw_data.get("candles", [])
        if not raw_candles: return []
        parsed = []
        for c in raw_candles:
            if isinstance(c, list) and len(c) >= 5:
                parsed.append({"time": int(c[0]), "open": float(c[1]), "close": float(c[2]), "high": float(c[3]), "low": float(c[4])})
            elif isinstance(c, dict) and "time" in c:
                parsed.append(c)
        return parsed

    async def get_historical_candles(self, asset, amount_of_seconds, period, timeout=30, max_workers=5, progress_callback=None):
        # ===== FIX 7: (5 workers + chunk=200) =====
        # .
        # (keepalive + watchdog ).
        max_workers = max_workers or 1
        chunk_seconds = period * FETCH_CHUNK_SIZE  # period * 200 = 12000s batch
        all_candles = {}
        current_time = int(time.time())
        target_start_time = current_time - amount_of_seconds
        block_size = amount_of_seconds // max_workers
        semaphore = asyncio.Semaphore(max_workers)

        async def worker(start_t, end_t, worker_id):
            worker_candles = {}
            async with semaphore:
                oldest_t = start_t
                consecutive_failures_in_worker = 0
                while oldest_t > end_t:
                    # ===== FIX 3: batch =====
                    if not self.api or not getattr(self.api.state, 'check_accepted_connection', False):
                        # —
                        break
                    index = next(_request_counter)
                    batch_data = await self._fetch_historical_batch(asset, oldest_t, chunk_seconds, period, index, timeout)
                    if not batch_data:
                        oldest_t -= chunk_seconds
                        consecutive_failures_in_worker += 1
                        if consecutive_failures_in_worker >= 3:
                            # 3 consecutive failures = connection dead — exit
                            break
                        # backoff
                        await asyncio.sleep(FETCH_BATCH_DELAY * 2)
                        continue
                    consecutive_failures_in_worker = 0
                    new_batch = self._parse_historical_candles(batch_data)
                    if not new_batch: oldest_t -= chunk_seconds; continue
                    batch_times = []
                    for c in new_batch:
                        ts = c['time']
                        if ts >= end_t and ts <= start_t:
                            worker_candles[ts] = c
                            batch_times.append(ts)
                    if not batch_times: oldest_t -= chunk_seconds; continue
                    batch_times.sort()
                    new_oldest = batch_times[0]
                    if progress_callback: progress_callback(start_t - new_oldest, start_t - end_t, len(worker_candles), f"Worker-{worker_id}")
                    oldest_t = new_oldest if new_oldest < oldest_t else oldest_t - chunk_seconds
                    # batches (0.1s — )
                    await asyncio.sleep(FETCH_BATCH_DELAY)
            return list(worker_candles.values())

        await self.start_candles_stream(asset, period)
        tasks = []
        for i in range(max_workers):
            s = current_time - (i * block_size)
            e = max(target_start_time, s - block_size)
            tasks.append(worker(s, e, i))
        results = await asyncio.gather(*tasks)
        for batch in results:
            for c in batch: all_candles[c['time']] = c
        return sorted(all_candles.values(), key=lambda x: x['time'])

    def prepare_candles(self, asset, period, history=None):
        if self.api is None: return []
        history_data = history if history is not None else self.api.candles.candles_data
        if history_data is None: return []
        if isinstance(history_data, dict):
            candles_list = history_data.get("candles") or history_data.get("data") or history_data.get("history") or []
        else:
            candles_list = history_data
        if not candles_list: return []
        # ===== FIX A: _parse_raw_candles calculate_candles =====
        # calculate_candles tick [time, price]
        # tick[1] open/high/low/close — (open == high ==
        # low == close) history/load
        # [time, open, close, high, low]. _parse_raw_candles
        # .
        candles_data = _parse_raw_candles(candles_list)
        # grill period ( )
        for c in candles_data:
            c['time'] = (int(c['time']) // period) * period
        candles_v2_data = process_candles_v2(self.api.candle_v2_data, asset, candles_data)
        return merge_candles(candles_v2_data)

    async def close(self):
        if self.api: return await self.api.close()
        return True

# ==============================================================================
# SECTION 8: MT4 WRITER & ASSETS (COMPLETE)
# ==============================================================================
os.environ['SSL_CERT_FILE'] = cert_path
os.environ['WEBSOCKET_CLIENT_CA_BUNDLE'] = cert_path

DEBUG_LOGS = False
def dbg(msg: str):
    if DEBUG_LOGS: print(f"  \033[2m   [debug] {msg}\033[0m")

LOG_FILE = Path("qxchart.log")
def _log_to_file(line: str):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f: f.write(line + "\n")
    except Exception: pass

def logmsg(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    _log_to_file(line)
    # If live table is active, queue the message instead of printing directly
    # to avoid corrupting the redrawn table
    if '_STATUS_MESSAGES_QUEUE' in globals() and globals()['_STATUS_MESSAGES_QUEUE'] is not None:
        try:
            globals()['_STATUS_MESSAGES_QUEUE'].append(line)
            # keep last 5 messages
            if len(globals()['_STATUS_MESSAGES_QUEUE']) > 5:
                globals()['_STATUS_MESSAGES_QUEUE'] = globals()['_STATUS_MESSAGES_QUEUE'][-5:]
        except Exception:
            pass
    else:
        print(f"  \033[2m[{ts}]\033[0m {msg}")

def log_exception(context: str, exc: BaseException):
    ts = datetime.now().strftime("%H:%M:%S")
    tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(f"  \033[91m[{ts}] FATAL in {context}: {exc}\033[0m")
    _log_to_file(f"[{ts}] FATAL in {context}: {exc}\n{tb_text}")

def _thread_excepthook(args):
    log_exception(f"thread '{args.thread.name}'", args.exc_value)
threading.excepthook = _thread_excepthook

def _main_excepthook(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt): sys.__excepthook__(exc_type, exc_value, exc_tb); return
    log_exception("main thread (top level)", exc_value)
sys.excepthook = _main_excepthook

class _NullHandler(logging.Handler):
    def emit(self, record): pass

@contextlib.contextmanager
def suppress_terminal_output():
    _loggers = [logging.getLogger(), logging.getLogger("pyquotex"), logging.getLogger("Quotex"), logging.getLogger("websockets"), logging.getLogger("websocket"), logging.getLogger("asyncio")]
    _old_levels = [(l, l.level, l.disabled) for l in _loggers]
    _old_handlers = [(l, list(l.handlers)) for l in _loggers]
    for l in _loggers:
        l.handlers = [_NullHandler()]; l.setLevel(logging.CRITICAL + 1); l.disabled = True
    with open(os.devnull, 'w') as devnull:
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = devnull, devnull
        try: yield
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
            for l, lvl, dis in _old_levels: l.setLevel(lvl); l.disabled = dis
            for l, hs in _old_handlers: l.handlers = hs

WINAPI_AVAILABLE = False
if platform.system() == "Windows":
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        WM_COMMAND = 0x0111
        MT4_REFRESH_CHART = 33324
        GA_ROOT = 2
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.PostMessageW.restype = wintypes.BOOL
        user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
        user32.GetAncestor.restype = wintypes.HWND
        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        user32.IsWindowVisible.restype = wintypes.BOOL
        user32.IsWindow.argtypes = [wintypes.HWND]
        user32.IsWindow.restype = wintypes.BOOL
        user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, wintypes.INT]
        user32.GetWindowTextW.restype = wintypes.INT
        user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        user32.GetWindowTextLengthW.restype = wintypes.INT
        WINAPI_AVAILABLE = True
    except Exception: pass

_MT4_HWND = None
_MT4_HWND_LAST_SEARCH = 0
_LAST_GLOBAL_REFRESH = 0
_ENUM_PROC_REF = None

def find_mt4_window():
    global _MT4_HWND, _MT4_HWND_LAST_SEARCH, _ENUM_PROC_REF
    if not WINAPI_AVAILABLE: return None
    now = time.time()
    if _MT4_HWND and (now - _MT4_HWND_LAST_SEARCH < 30):
        if user32.IsWindow(_MT4_HWND): return _MT4_HWND
    _MT4_HWND = None
    _MT4_HWND_LAST_SEARCH = now
    found = []
    @ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    def enum_callback(hwnd, lparam):
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                if "MetaTrader 4" in buf.value or "MetaTrader4" in buf.value: found.append(hwnd)
                return False
        return True
    _ENUM_PROC_REF = enum_callback
    user32.EnumWindows(enum_callback, 0)
    _MT4_HWND = found[0] if found else None
    return _MT4_HWND

REFRESH_INTERVAL = 1.0
def refresh_mt4():
    global _LAST_GLOBAL_REFRESH
    if not WINAPI_AVAILABLE: return False
    now = time.time()
    if now - _LAST_GLOBAL_REFRESH < REFRESH_INTERVAL: return False
    _LAST_GLOBAL_REFRESH = now
    hwnd = find_mt4_window()
    if not hwnd: return False
    root = user32.GetAncestor(hwnd, GA_ROOT)
    target = root if root else hwnd
    user32.PostMessageW(target, WM_COMMAND, MT4_REFRESH_CHART, 0)
    return True

class Colors:
    GREEN = '\033[92m'; RED = '\033[91m'; BLUE = '\033[94m'; YELLOW = '\033[93m'
    CYAN = '\033[96m'; BOLD = '\033[1m'; DIM = '\033[2m'; RESET = '\033[0m'; CLEAR_LINE = '\033[K'
    # ===== ألوان إضافية مطلوبة للواجهة الجديدة (v3 UI) =====
    WHITE = '\033[97m'      # أبيض ساطع
    MAGENTA = '\033[95m'    # بنفسجي ساطع
    GRAY = '\033[90m'       # رمادي

def _current_period_label() -> str:
    # Subsecond labels
    if IS_SUBSECOND and SUBSECOND_LABEL:
        return SUBSECOND_LABEL
    if PERIOD >= 1440 and PERIOD % 1440 == 0:
        d = PERIOD // 1440
        return f"D{d}" if d > 1 else "D1"
    if PERIOD >= 60 and PERIOD % 60 == 0:
        h = PERIOD // 60
        return f"H{h}" if h > 1 else "H1"
    return f"M{PERIOD}"

def pretty_asset_name(symbol: str, period_label: str = None) -> str:
    if period_label is None:
        period_label = _current_period_label()
    base = symbol
    suffix = ""
    if base.upper().endswith("_OTC"):
        base = base[:-4]
        suffix = " · OTC"
    if len(base) == 6 and base.isalpha():
        pretty = f"{base[:3].upper()}/{base[3:].upper()}{suffix}"
    else:
        pretty = f"{base.upper()}{suffix}"
    return f"({pretty}),{period_label}"

user_home = os.path.expanduser('~')
MT4_CONFIG_FILE = Path("mt4_config.json")
# ===== FIX J: digits — =====
# : " " —
# .
# mt4_digits.json:
# {
# "global_digits": null, // null = ; ( 5)
# "overrides": {
# "USDIDR-OTC": 4,
# "USDPKR-OTC": 5
# }
# }
DIGITS_CONFIG_FILE = Path("mt4_digits.json")
_digits_config_cache = None
_digits_config_loaded = False

def load_digits_config() -> dict:
    """ mt4_digits.json . ."""
    global _digits_config_cache, _digits_config_loaded
    try:
        if DIGITS_CONFIG_FILE.exists():
            mtime = DIGITS_CONFIG_FILE.stat().st_mtime
            if not _digits_config_loaded or _digits_config_cache.get('_mtime', 0) < mtime:
                _digits_config_cache = json.loads(DIGITS_CONFIG_FILE.read_text())
                _digits_config_cache['_mtime'] = mtime
                _digits_config_loaded = True
        elif _digits_config_loaded:
            # —
            _digits_config_cache = None
            _digits_config_loaded = False
    except Exception:
        return {}
    return _digits_config_cache if _digits_config_cache else {}

def _resolve_digits(symbol: str, price: float = 0.0) -> int:
    """ .
 
 :
 1) per-asset mt4_digits.json ("overrides")
 2) mt4_digits.json ("global_digits")
 3) ( )
 
 (FIX J):
 - JPY: 3 ()
 - < 0.5: 6 (was 6) — BRLUSD
 - < 1: 5 (was 5)
 - < 5: 5 (was 5)
 - < 10: 4 (was 4)
 - < 50: 4 (was 4)
 - < 100: 3 (was 3)
 - < 1000: 3 (was 2) ← FIX J: 100-1000
 - < 10000: 3 (was 2) ← FIX J
 - >= 10000: 3 (was 2) ← FIX J
 : >= 100 digits=2 (min grid 0.01) — .
 : >= 100 digits=3 (min grid 0.001) — 
 mt4_digits.json.
 """
    sym_upper = symbol.upper()
    # 1) per-asset override
    cfg = load_digits_config()
    if cfg:
        overrides = cfg.get('overrides', {}) or {}
        if sym_upper in overrides:
            try:
                d = int(overrides[sym_upper])
                if 0 <= d <= 8:
                    return d
            except (TypeError, ValueError):
                pass
        # 2) global override
        global_d = cfg.get('global_digits', None)
        if global_d is not None:
            try:
                d = int(global_d)
                if 0 <= d <= 8:
                    return d
            except (TypeError, ValueError):
                pass
    # 3) auto calculation (improved FIX J defaults)
    if "JPY" in sym_upper: return 3
    if price and price > 0:
        if price < 0.5:  return 6
        if price < 1:    return 5
        if price < 5:    return 5
        if price < 10:   return 4
        if price < 50:   return 4
        if price < 100:  return 3
        # FIX J: >= 100 digits=3 ( 2)
        # → (0.001 0.01)
        return 3
    # fallback when no price
    if any(x in sym_upper for x in ["IDR", "COP", "ARS", "NGN", "PKR", "DZD", "EGP", "MXN", "PHP", "INR", "BDT", "ZAR", "BRL"]):
        return 3  # FIX J: was 2
    return 5
SYSTEM_FOLDERS = {"default", "downloads", "mailbox", "signals", "symbolsets", "deleted", "templates", "profiles", "mql4", "logs", "config", "history_backup"}

def _validate_mt4_path(path: str) -> bool:
    if not path or not os.path.exists(path): return False
    try:
        test_file = os.path.join(path, ".write_test.tmp")
        with open(test_file, 'w') as f: f.write("test")
        os.remove(test_file)
        return True
    except Exception: return False

def _save_mt4_path(path: str):
    try:
        config = json.loads(MT4_CONFIG_FILE.read_text()) if MT4_CONFIG_FILE.exists() else {}
        config["mt4_history_path"] = path
        config["saved_at"] = int(time.time())
        MT4_CONFIG_FILE.write_text(json.dumps(config, indent=2))
    except Exception: pass

def find_mt4_history_path() -> str:
    appdata = os.environ.get('APPDATA', '') or os.environ.get('HOME', '')
    common_path = os.path.join(appdata, 'MetaQuotes', 'Terminal', 'Common', 'Files', 'qx_hst')
    try:
        os.makedirs(common_path, exist_ok=True)
        return common_path
    except Exception:
        pass
    
    base_terminal = os.path.join(user_home, "AppData", "Roaming", "MetaQuotes", "Terminal")
    if not os.path.exists(base_terminal): return ""
    all_servers = []
    try:
        for terminal_id in os.listdir(base_terminal):
            history_path = os.path.join(base_terminal, terminal_id, "history")
            if not os.path.exists(history_path): continue
            for server_name in os.listdir(history_path):
                server_lower = server_name.lower()
                if server_lower in SYSTEM_FOLDERS or server_lower.startswith(".") or server_lower.startswith("_"): continue
                server_path = os.path.join(history_path, server_name)
                if not os.path.isdir(server_path): continue
                try:
                    hst_files = [f for f in os.listdir(server_path) if f.endswith('.hst')]
                    all_servers.append({"terminal_id": terminal_id, "server_name": server_name, "full_path": server_path, "has_hst": len(hst_files) > 0, "hst_count": len(hst_files), "is_writable": _validate_mt4_path(server_path)})
                except Exception: pass
    except Exception: pass
    if not all_servers: return ""
    if MT4_CONFIG_FILE.exists():
        try:
            saved_path = json.loads(MT4_CONFIG_FILE.read_text()).get("mt4_history_path", "")
            if saved_path and os.path.exists(saved_path):
                for srv in all_servers:
                    if srv["full_path"] == saved_path and srv["is_writable"]: return saved_path
        except Exception: pass
    writable_servers = [s for s in all_servers if s["is_writable"]]
    if not writable_servers: return ""
    servers_with_hst = [s for s in writable_servers if s["has_hst"]]
    if servers_with_hst:
        servers_with_hst.sort(key=lambda x: (-x["hst_count"], x["server_name"]))
        chosen = servers_with_hst[0]
        _save_mt4_path(chosen["full_path"])
        return chosen["full_path"]
    chosen = writable_servers[0]
    _save_mt4_path(chosen["full_path"])
    return chosen["full_path"]

MT4_HISTORY_PATH = find_mt4_history_path()
if not MT4_HISTORY_PATH:
    MT4_HISTORY_PATH = os.path.join(user_home, "Desktop", "MT4_History_Fallback")
    os.makedirs(MT4_HISTORY_PATH, exist_ok=True)

SESSION_FILE = Path("session.json")
SESSION_STATE_FILE = Path("session_state.json")
EMAIL_FILE = Path("saved_email.txt")

class SessionManager:
    def __init__(self): self.state = self._load_state()
    def _load_state(self) -> dict:
        try:
            if SESSION_STATE_FILE.exists(): return json.loads(SESSION_STATE_FILE.read_text())
        except Exception: pass
        return {"last_login": 0, "last_success": False, "failed_auth_count": 0, "email": "", "host": "qxbroker.com"}
    def _save_state(self):
        try: SESSION_STATE_FILE.write_text(json.dumps(self.state, indent=2))
        except Exception: pass
    def should_force_fresh(self) -> bool:
        if not self.state.get("last_success", False): return True
        if self.state.get("failed_auth_count", 0) >= 2: return True
        if time.time() - self.state.get("last_login", 0) > 7 * 24 * 3600: return True
        return False
    def record_success(self, email: str, host: str = None):
        # FIX K:
        update_dict = {"last_login": time.time(), "last_success": True, "failed_auth_count": 0, "email": email}
        if host: update_dict["host"] = host
        self.state.update(update_dict)
        self._save_state()
        EMAIL_FILE.write_text(email)
    def record_failure(self, error: str):
        self.state["last_login"] = time.time()
        self.state["last_success"] = False
        self.state["failed_auth_count"] = self.state.get("failed_auth_count", 0) + 1
        self._save_state()
    def get_saved_email(self) -> str:
        email = self.state.get("email", "")
        return email if email else (EMAIL_FILE.read_text().strip() if EMAIL_FILE.exists() else "")

    def get_saved_host(self) -> str:
        # FIX K:
        return self.state.get("host", "qxbroker.com")
    @staticmethod
    def delete_session_file():
        if SESSION_FILE.exists():
            try: SESSION_FILE.unlink(); return True
            except Exception: pass
        return False
    @staticmethod
    def delete_browser_dir():
        browser_dir = Path("browser")
        if browser_dir.exists():
            try: shutil.rmtree(browser_dir, ignore_errors=True); return True
            except Exception: pass
        return False

session_manager = SessionManager()

# ==============================================================================
# UPDATED ASSET LIST & CANDLE COUNT SETTINGS
# ==============================================================================
ASSET_LIST = [
    "BRLUSD_otc", "USDARS_otc", "USDBDT_otc", "USDCOP_otc", "USDEGP_otc",
    "USDIDR_otc", "USDINR_otc", "USDMXN_otc", "USDNGN_otc", "USDPHP_otc",
    "USDPKR_otc", "USDZAR_otc", "AUDCAD_otc", "AUDCHF_otc", "AUDJPY_otc",
    "AUDNZD_otc", "AUDUSD_otc", "CADCHF_otc", "CADJPY_otc", "CHFJPY_otc",
    "EURAUD_otc", "EURCAD_otc", "EURCHF_otc", "EURGBP_otc", "EURJPY_otc",
    "EURNZD_otc", "EURUSD_otc", "GBPAUD_otc", "GBPCAD_otc", "GBPCHF_otc",
    "GBPJPY_otc", "GBPNZD_otc", "GBPUSD_otc", "NZDCAD_otc", "NZDCHF_otc",
    "NZDJPY_otc", "NZDUSD_otc", "USDCAD_otc", "USDCHF_otc", "USDDZD_otc", "USDJPY_otc",
]

TIMEFRAMES = [
    (1,    60,      "M1  - 1 minute",      False),
    (2,    120,     "M2  - 2 minutes",     False),
    (3,    180,     "M3  - 3 minutes",     False),
    (5,    300,     "M5  - 5 minutes",     False),
    (10,   600,     "M10 - 10 minutes",    False),
    (15,   900,     "M15 - 15 minutes",    False),
    (30,   1800,    "M30 - 30 minutes",    False),
    (60,   3600,    "H1  - 1 hour",        False),
    (240,  14400,   "H4  - 4 hours",       False),
    (1440, 86400,   "D1  - 1 day",         False),
    # Subsecond timeframes (aggregated locally from realtime ticks, no history API)
    (1,    5,       "S5  - 5 seconds",     True),
    (1,    10,      "S10 - 10 seconds",    True),
    (1,    15,      "S15 - 15 seconds",    True),
    (1,    30,      "S30 - 30 seconds",    True),
]

PERIOD = 1
PERIOD_SECONDS = 60
# Subsecond mode globals — set when user chooses S5/S10/S15/S30
IS_SUBSECOND = False
SUBSECOND_SECONDS = 0   # 5, 10, 15, or 30
SUBSECOND_LABEL = ""    # "5S", "10S", "15S", "30S"
SUBSECOND_MAX_CANDLES = 500  # v8.1: raised from 200 -> 500 to match SUBSECOND_HISTORY_CANDLES (user asked: keep >=500 5s candles in memory)
SUBSECOND_HISTORY_CANDLES = 500  # fetch up to 500 historical subsecond candles at startup (was 1000, reduced for speed)
# Semaphore to limit concurrent subsecond history fetches (3 at a time, not 41)
# Created lazily on first use to avoid event loop binding issues at import time
_SUBSECOND_FETCH_SEMAPHORE = None
# v8.1: explicit asset-to-asset delay for subsecond mode (user asked: ~1 second between currencies)
SUBSECOND_ASSET_DELAY = 2.0   # v8.3: raised from 1.0 -> 2.0 (server needs more breathing room between assets)
# v8.3: target fewer 1s candles -- the server throttles after ~5 chunks per asset, so 2.0x margin
# was pointless (we'd never reach it anyway). 1.3x targets 3250 1s = enough for 500 5s after dedup.
SUBSECOND_FETCH_MARGIN = 1.3  # v8.3: was 2.0 -- reduced to lower request count per asset
SUBSECOND_MAX_CHUNKS = 5      # v8.3: was 60 -- 5 chunks * 500s = 2500s = exactly 500 5s candles; more is wasted
# v8.3: user explicitly asked -- if the server returns >=85 5s candles from the first chunk, do not
# keep repeating the requests. Accept the server's per-asset history limit and move on.
SUBSECOND_EARLY_EXIT_CANDLES = 85  # stop fetching more chunks once we have >=85 aggregated 5s candles
# v8.3: graceful stop -- after this many consecutive zero-candle assets, the WebSocket is dead.
# Break the startup loop cleanly instead of burning 8 * 30s = 240s in reconnect attempts.
SUBSECOND_MAX_ZERO_STREAK = 3  # was effectively infinite (relied on MAX_RECONNECTS_DURING_FETCH=8)
# v8.4/v8.6: NEW feature for M1 timeframe -- fetch 1s candles first, aggregate
# to 1m, use them as the most granular bridge between the historical 1m fetch
# and the live stream. Disables the old _bridge_fetch_recent_candles for M1.
#
# v8.6 change: switched from 5s aggregation -> 1s aggregation. 1s is the most
# granular source -- if the server's 1s data is continuous, the aggregated 1m
# candle has NO gaps (60 consecutive 1s candles -> 1 perfect 1m candle). With
# 5s aggregation, a missing 5s candle leaves a partial gap in the 1m candle.
M1_USE_1S_BRIDGE = True       # set False to fall back to the old M1 bridge fetch
M1_1S_BRIDGE_TARGET = 750     # v8.6: target 1s candles for the bridge (=> ~12 1m candles)
M1_BRIDGE_TIMEOUT = 30        # seconds, bounded wait for the 1s fetch
# v8.11: delays to prevent server throttling in M1 bridge mode.
# User explicitly asked: "مهلات لكي لا لا يتوقف السرفر" (delays so the
# server doesn't stop). The pattern per asset is:
#   1s fetch -> M1_INTRA_ASSET_DELAY -> 1000 historical fetch -> M1_ASSET_DELAY -> next asset
M1_INTRA_ASSET_DELAY = 1.0    # v8.11: delay between 1s fetch and 1000 historical fetch (same asset)
M1_ASSET_DELAY = 1.0          # v8.11: delay between assets in M1 bridge mode (was 0.1s)
# v8.13: cap the bridge to the NEWEST N candles only, then REPLACE matching
# historical candles. User explicitly asked: "نربط 6 شموع الاولى فقط" (only
# bridge the first 6). The max gap between live stream and historical is 5
# candles, so 6 bridge candles guarantee full coverage. The server returns
# a variable count of 1s candles (8/12/13), so we always take the last 6.
M1_BRIDGE_REPLACE_COUNT = 6   # v8.13: only the newest N bridge candles replace historical
# v8.7: TEST MODE -- when True, for M1 timeframe, SKIP the 1000 historical
# 1m fetch entirely and display ONLY the 1s->1m aggregated candles on the chart.
# This lets us verify that the 1s aggregation produces valid 1m candles that MT4
# can render correctly. Once verified, set False to restore the full flow
# (historical 1000 1m + 1s->1m bridge merged).
# v8.10: TEST MODE disabled -- full flow is now active:
#   1) fetch 1s candles -> aggregate to 1m (8-13 bridge candles, no gaps)
#   2) fetch 1000 historical 1m candles via fetch_candles_with_retry
#   3) merge: [1000 historical] + [bridge where ts > last historical ts]
#   4) the bridge fills the 4-5 missing candles between historical and live
# Set to True to re-enter TEST MODE (1s->1m only, no historical fetch).
M1_TEST_1S_ONLY = False       # v8.10: TEST MODE disabled, full flow active
# ===== FIX 4: 1000 ( ) =====
# 500 1000 (4s).
# : workers=5 + chunk=200 ( ) .
INITIAL_CANDLES = 1000
MIN_CANDLES_THRESHOLD = 100
HISTORY_DAYS = 0.75
FETCH_DURATION_SECONDS = int(86400 * HISTORY_DAYS)
# v9.0: STREAM_POLL_INTERVAL reduced from 0.15s -> 0.05s for fastest possible tick updates.
# This is the loop inside realtime_stream / subsecond_stream that polls CLIENT.api.realtime_candles.
# Lower = faster live tick rendering on the chart.
STREAM_POLL_INTERVAL = 0.05
# v9.0: WRITE_HST_FILES_ENABLED = False — server no longer writes .hst files to disk.
# The web dashboard (Flask) is now the ONLY output channel. This eliminates disk I/O
# overhead and lets the bot run faster. Set to True if you still want HST files (e.g.,
# for MT4 direct loading). When False, asset.write() and MT4_WRITER.write_to_file() are no-ops.
WRITE_HST_FILES_ENABLED = False
# ===== FIX 4: WRITE_INTERVAL = 0.5s 3.0s ( 500ms) =====
WRITE_INTERVAL = 0.5
STALE_DATA_TIMEOUT = 180
STALE_RATIO_TRIGGER = 0.8
# ===== FIX 7: KEEPALIVE_PING_INTERVAL = 5s =====
# : " ".
# 10s (5 workers × 41 )
# keepalive . 5s .
KEEPALIVE_PING_INTERVAL = 5
RECONNECT_CHECK_INTERVAL = 1
RECONNECT_BASE_DELAY = 2
RECONNECT_MAX_DELAY = 30
STATUS_REFRESH_INTERVAL = 0.5
# ===== FIX 7: watchdog =====
# .
# STALE_MESSAGE_TIMEOUT=45s + STALE_WATCHDOG_INTERVAL=5s
# => latency = 45-50s ( )
# FIX 7: STALE_MESSAGE_TIMEOUT=20s + STALE_WATCHDOG_INTERVAL=3s
# => latency = 20-23s ( ~2x)
STALE_MESSAGE_TIMEOUT = 20
STALE_WATCHDOG_INTERVAL = 3  # 3s (was 5s)
ENGINEIO_PING_INTERVAL = 20  # "2" (engine.io ping) 20s — Socket.IO EIO=3
# ===== FIX 4: 4s 1000 =====
# ( 4s 1000 ):
# max_workers=5, chunk=period*200 (12000s), delay=0.1s
# : :
# - FETCH_ASSET_DELAY (0.1s)
# - workers ( FIX 3)
# - exponential backoff retry ( FIX 3)
# - main loop ( FIX 3)
# : 4s + ( FIX 1+2 )
FETCH_MAX_WORKERS = 5          # 5 workers (reverted — 10 caused connection drops)
FETCH_CHUNK_SIZE = 200         # 200 candles per batch (reverted)
FETCH_BATCH_DELAY = 0.1        # 0.1s between batches (reverted)
FETCH_ASSET_DELAY = 0.1        # 0.1s between assets (reverted)
# ===== FIX 7: cooldown — =====
FETCH_COOLDOWN_EVERY = 0       # 0 =
FETCH_COOLDOWN_DURATION = 0.0  # 0 =
FETCH_TIMEOUT = 30             # 30s per batch (reverted)
RETRY_BACKOFF_BASE = 2         # exponential backoff base
RETRY_BACKOFF_MAX = 15         # max delay between retries (reverted)
MAX_FETCH_RETRIES = 5          # 5 attempts (reverted)

MAX_RECONNECTS_DURING_FETCH = 8
# ===== FIX L1: gap fill 120 () 20 =====
# : " "
# 20 (20 ) 20 — .
# 120 () /.
GAP_FILL_CANDLES = 10  # fetch 10 recent candles to replace incomplete ones
# ===== FIX L1: 5 ( ) =====
# : _gap_filled = True => .
# : GAP_FILL_REFRESH_INTERVAL .
GAP_FILL_REFRESH_INTERVAL = 300  # 5

# ==============================================================================
# ===== BRIDGE FETCH (سد فجوة 4-5 شموع بين التاريخي والبث المباشر) =====
# ==============================================================================
# المشكلة: بعد انتهاء الجلب التاريخي (الذي يستغرق 5-15 ثانية)، يكون البث قد بدأ
#   لكن الخادم يؤجل إرسال ticks بسبب ضغط طلبات history/load. النتيجة: فجوة 4-5 شموع.
# الحل: بعد اكتمال الجلب التاريخي، اطلب آخر شموع تنتهي عند time.time() الحالي
#   (وليس T0). هذا يملأ الفجوة بين آخر شمعة تاريخية وأول شمعة بث مباشر.
# الأمان:
#   - BRIDGE_FETCH_ENABLED=False يُعطّل الميزة فوراً دون أي تأثير جانبي
#   - كل الأعمدة محاطة بـ try/except (الخطأ لا يُكسر الجلب التاريخي)
#   - Semaphore يمنع إرهاق الخادم بطلبات جسر متزامنة
#   - يستخدم get_candles الموجودة (دالة مُجرّبة وآمنة)
BRIDGE_FETCH_ENABLED = True       # مفتاح التشغيل/الإيقاف الرئيسي
BRIDGE_FETCH_CANDLES = 15         # عدد الشموع لجلب الجسر (يكفي لفجوة كبيرة + هامش أمان)
BRIDGE_FETCH_TIMEOUT = 20         # مهلة الجلب الجسري (ثانية) — زادت من 15 إلى 20
BRIDGE_FETCH_SEMAPHORE_LIMIT = 2  # أقصى عدد طلبات جسر متزامنة (لمنع إرهاق الخادم)
_BRIDGE_FETCH_SEMAPHORE = None    # يُنشأ تلقائياً عند أول استخدام (lazy init)

# ===== FIX L2: — =====
# : _is_dst time.altzone/time.timezone
# Windows ( DST
# DST — Africa/Algiers).
# : / HST → MT4.
# : datetime.now().astimezone().utcoffset() ( )
# .
try:
    from datetime import datetime as _dt_naive
    _SYSTEM_TZ_OFFSET = int(_dt_naive.now().astimezone().utcoffset().total_seconds())
except Exception:
    _SYSTEM_TZ_OFFSET = -time.timezone  # fallback ( )
# ===== " " : =====
# :
# LOCAL_TZ_OFFSET_SECONDS = 3600 # UTC+1 ( )
# LOCAL_TZ_OFFSET_SECONDS = 0 # UTC ( )
# LOCAL_TZ_OFFSET_SECONDS = 7200 # UTC+2 ( )
# LOCAL_TZ_OFFSET_SECONDS = 10800 # UTC+3 ( )
# None .
LOCAL_TZ_OFFSET_SECONDS = None  # None = _SYSTEM_TZ_OFFSET

def _get_tz_offset() -> int:
    """ (UTC → ). ."""
    if LOCAL_TZ_OFFSET_SECONDS is not None:
        return LOCAL_TZ_OFFSET_SECONDS
    return _SYSTEM_TZ_OFFSET

def _align_time(raw_ts: int, period_seconds: int = None) -> int:
    """Aligns a raw timestamp to period boundary after applying TZ offset.

 period_seconds=None reads PERIOD_SECONDS global dynamically (multi-timeframe support).
 """
    if period_seconds is None:
        period_seconds = PERIOD_SECONDS
    tz = _get_tz_offset()
    return ((int(raw_ts) + tz) // period_seconds) * period_seconds

# Fill missing slots with flat candles. max_gap=1440 (full day) allows filling
# gaps up to 1 day. period_seconds=None reads PERIOD_SECONDS dynamically.
def _fill_missing_slots(candles: list, period_seconds: int = None,
                        max_gap: int = 1440) -> list:
    """Fills time gaps between candles with flat candles (previous close).

 - Added candles have volume=0 (marked synthetic).
 - max_gap: max number of periods to fill (1440 = 1 day for M1).
 - period_seconds=None reads PERIOD_SECONDS dynamically (multi-timeframe).
 """
    if period_seconds is None:
        period_seconds = PERIOD_SECONDS
    if len(candles) < 2:
        return list(candles)
    candles = sorted(candles, key=lambda x: x['time'])
    out = [dict(candles[0])]
    for i in range(1, len(candles)):
        prev = out[-1]
        curr = candles[i]
        gap = (curr['time'] - prev['time']) // period_seconds
        if 0 < gap <= max_gap:

            slot = prev['time'] + period_seconds
            while slot < curr['time']:
                out.append({
                    'time': slot,
                    'open': prev['close'],
                    'high': prev['close'],
                    'low': prev['close'],
                    'close': prev['close'],
                    'volume': 0,
                })
                slot += period_seconds
        out.append(dict(curr))
    return out

# Aggregate 1-second candles into target_period (5s, 10s, 15s, 30s) candles.
# Used for sub-60s timeframes: fetch period=1 from server, aggregate locally.
def _aggregate_sub_minute(candles: list, target_period: int) -> list:
    """Aggregate 1-second candles into target_period candles.

    For each group of (target_period) consecutive 1s candles:
    - time = first candle's time aligned to target_period boundary
    - open = first candle's open
    - high = max of all highs
    - low = min of all lows
    - close = last candle's close
    - volume = sum of all volumes
    """
    if not candles or target_period <= 1:
        return list(candles)
    candles = sorted(candles, key=lambda x: x['time'])
    buckets = OrderedDict()
    for c in candles:
        bucket_time = (c['time'] // target_period) * target_period
        if bucket_time not in buckets:
            buckets[bucket_time] = {
                'time': bucket_time,
                'open': c['open'],
                'high': c['high'],
                'low': c['low'],
                'close': c['close'],
                'volume': int(c.get('volume', 0) or 0),
            }
        else:
            b = buckets[bucket_time]
            b['high'] = max(b['high'], c['high'])
            b['low'] = min(b['low'], c['low'])
            b['close'] = c['close']
            b['volume'] += int(c.get('volume', 0) or 0)
    return list(buckets.values())

# ===== FIX K: Quotex =====
# Domain list. Labels are intentionally NEUTRAL (no country/region labels) so
# no user feels singled out. Just the domain name as the broker publishes it.
DOMAINS = [
    ("qxbroker.com",    "qxbroker.com"),
    ("market-qx.info",  "market-qx.info"),
]
# — session_state
QX_HOST = "qxbroker.com"

ASYNC_LOOP = None
ASYNC_ENGINE_GENERATION = 0
_ENGINE_READY = threading.Event()
CONNECTION_ALIVE = False
CLIENT = None
EMAIL = None
PASSWORD = None
RECONNECTING = False
ALL_STREAMING_ASSETS = []
LAST_HEALTH_CHECK = 0
HEALTH_CHECK_INTERVAL = 20
# ===== FIX B: =====
# : " ".
# —
# 1000 .
LAST_CONNECTION_DROP_TIME = 0            # 0 =
LONG_DISCONNECT_THRESHOLD = 3600        # 3600s = 1
# ===== FIX F: =====
# mt4_gap_filler print()
# 0.5s →
# . : .
GAP_FILL_SUMMARY = ""  # ( mt4_gap_filler)
_STATUS_MESSAGES_QUEUE = []  # queue for log messages during live table (avoid corrupting redraw)
GAP_FILL_ACTIVE = False  # True

def _asyncio_loop_exception_handler(loop, context):
    exc = context.get("exception")
    if exc: log_exception(f"asyncio loop (gen {ASYNC_ENGINE_GENERATION})", exc)

def start_async_engine():
    global ASYNC_LOOP, ASYNC_ENGINE_GENERATION, CONNECTION_ALIVE
    while True:
        try:
            ASYNC_ENGINE_GENERATION += 1
            gen = ASYNC_ENGINE_GENERATION
            new_loop = asyncio.new_event_loop()
            new_loop.set_exception_handler(_asyncio_loop_exception_handler)
            asyncio.set_event_loop(new_loop)
            ASYNC_LOOP = new_loop
            _ENGINE_READY.set()
            if gen > 1:
                logmsg(f"[AsyncEngine] event loop recreated (gen {gen}). Rescheduling tasks...")
                CONNECTION_ALIVE = False
                asyncio.run_coroutine_threadsafe(health_monitor(), ASYNC_LOOP)
                asyncio.run_coroutine_threadsafe(auto_reconnect(), ASYNC_LOOP)
                asyncio.run_coroutine_threadsafe(keepalive_loop(), ASYNC_LOOP)
                # ===== FIX: stale watchdog loop =====
                asyncio.run_coroutine_threadsafe(stale_message_watchdog(), ASYNC_LOOP)
                for asset in ALL_STREAMING_ASSETS:
                    asset.stream_task = None
                    asset.streaming = False
            new_loop.run_forever()
        except Exception as e:
            log_exception(f"AsyncEngine (gen {ASYNC_ENGINE_GENERATION})", e)
            CONNECTION_ALIVE = False
            time.sleep(1)

async_thread = threading.Thread(target=start_async_engine, daemon=True, name="AsyncEngine")
async_thread.start()
_ENGINE_READY.wait(timeout=10)

class Asset:
    @staticmethod
    def _derive_mt4_symbol(raw_symbol: str) -> str:
        s = raw_symbol.strip()
        is_otc = s.upper().endswith("_OTC")
        if is_otc:
            base = s[:-4].upper()
            if PERIOD_SECONDS < 60:
                # Sub-minute: compact name "AUDUSDOTC5S" (11 chars, fits 12-byte header)
                result = f"{base}OTC{SUBSECOND_LABEL}"
            else:
                result = f"{base}-OTC"
        else:
            if PERIOD_SECONDS < 60:
                result = f"{s.upper()}{SUBSECOND_LABEL}"
            else:
                result = s.upper()
        return result[:12] if result else raw_symbol.upper()[:12]

    def __init__(self, symbol):
        self.api_symbol = symbol
        self.symbol = self._derive_mt4_symbol(symbol)
        self.period = PERIOD
        self.price = 0.0
        self.previous_price = 0.0
        # For sub-minute: filename = {symbol}1.hst (e.g., AUDUSD-5S1.hst)
        # symbol is "AUDUSD-5S" (compact, fits 12-byte HST header)
        # For 60s+: filename = {symbol}{PERIOD}.hst (e.g., AUDUSD-OTC5.hst)
        if PERIOD_SECONDS < 60:
            self.path = os.path.join(MT4_HISTORY_PATH, f"{self.symbol}1.hst")
        else:
            self.path = os.path.join(MT4_HISTORY_PATH, f"{self.symbol}{PERIOD}.hst")
        self.candles = []
        self.last_write = 0.0
        self.updates = 0
        self.streaming = False
        self.stream_task = None
        self.last_update_time = 0
        self.last_saved_close = 0.0
        self.last_saved_candle_time = 0
        self.last_saved_candle_count = 0
        self.dirty = False
        self._gap_filled = False

    def digits(self, price: float = None) -> int:
        # FIX J: _resolve_digits ( mt4_digits.json)
        p = price if price is not None else self.price
        return _resolve_digits(self.symbol, p or 0.0)

    def has_new_data(self):
        if not self.candles: return False
        c = self.candles[-1]
        return (c['close'] != self.last_saved_close or c['time'] != self.last_saved_candle_time or len(self.candles) != self.last_saved_candle_count)

    def mark_dirty(self): self.dirty = True

    def write(self, force=False):
        # v9.0: skip HST writing entirely when WRITE_HST_FILES_ENABLED is False.
        # The web dashboard (Flask) is the only output channel.
        if not WRITE_HST_FILES_ENABLED:
            return False
        if not force and not self.has_new_data(): return False
        temp = self.path + ".tmp"
        # For sub-minute timeframes, write period=1 (M1) in the header so MT4 opens it
        header_period = 1 if PERIOD_SECONDS < 60 else self.period
        try:
            with open(temp, 'wb') as f:
                f.write(struct.pack('<i', 400))
                f.write(b"(C)opyright 2003, MetaQuotes Software Corp.".ljust(64, b'\0'))
                f.write(self.symbol.encode('ascii').ljust(12, b'\0')[:12])
                f.write(struct.pack('<i', header_period))
                first_price = self.candles[0]['close'] if self.candles else self.price
                f.write(struct.pack('<i', self.digits(first_price)))
                f.write(struct.pack('<i', int(time.time())))
                f.write(struct.pack('<i', int(time.time())))
                f.write(b'\0' * 52)
                for c in self.candles:
                    f.write(struct.pack('<i', c['time']))
                    f.write(struct.pack('<d', c['open']))
                    f.write(struct.pack('<d', c['low']))
                    f.write(struct.pack('<d', c['high']))
                    f.write(struct.pack('<d', c['close']))
                    f.write(struct.pack('<q', int(c.get('volume', 0))))
            # ===== FIX 4: WinError 5 (Access Denied) + WinError 32 =====
            # WinError 32. WinError 5 (Access Denied)
            # MT4 ( ).
            # : retry WinError 5 + 32 + fallback.
            def _is_lock_error(err_str):
                err_str = err_str.lower()
                return (
                    "winerror 32" in err_str or
                    "used by another process" in err_str or
                    "winerror 5" in err_str or
                    "access denied" in err_str or
                    "accès refusé" in err_str or
                    "acces refusé" in err_str or
                    "permission" in err_str
                )
            replaced = False
            for attempt in range(8):  # 8 5
                try:
                    os.replace(temp, self.path)
                    replaced = True
                    break
                except (PermissionError, OSError) as e:
                    err_str = str(e)
                    if _is_lock_error(err_str):
                        # : 50ms, 100ms, 150ms, 200ms, 250ms...
                        time.sleep(0.05 + 0.05 * attempt)
                        continue
                    raise
            if not replaced:
                # ===== FIX 4: fallback — rename =====
                # os.replace 8 .
                try:
                    with open(self.path, 'wb') as f:
                        # (header + candles)
                        with open(temp, 'rb') as src:
                            f.write(src.read())
                    replaced = True
                except Exception as fallback_err:
                    if not _is_lock_error(str(fallback_err)):
                        logmsg(f"[write:{self.symbol}] fallback write failed: {fallback_err}")
            try:
                if os.path.exists(temp): os.remove(temp)
            except Exception: pass
            if replaced:
                self.last_write = time.time()
                if self.candles:
                    self.last_saved_close = self.candles[-1]['close']
                    self.last_saved_candle_time = self.candles[-1]['time']
                    self.last_saved_candle_count = len(self.candles)
                self.dirty = False
                return True
            return False
        except Exception as e:
            err_str = str(e).lower()
            # ===== FIX 8: WinError 2 (file not found) + WinError 5 + 32 =====
            # — retry .
            if not any(x in err_str for x in [
                'winerror 2', 'winerror 5', 'winerror 32', 'winerror 13',
                'introuvable', 'refusé', 'access', 'permission', 'used by another',
                'ebusy', 'eperm', 'no such file'
            ]):
                logmsg(f"[write:{self.symbol}] write failed: {e}")
            try:
                if os.path.exists(temp): os.remove(temp)
            except Exception: pass
            return False

class WriterThread(threading.Thread):
    """FIX 11: WriterThread — HST 500ms Asset.write.
 
 : (1000 4s).
 :
 - fetch_candles_with_retry (1000 )
 - Asset.write HST {derived_symbol}{PERIOD}.hst (AUDJPY-OTC1.hst)
 - WriterThread asset.dirty 100ms + HST 500ms
 
 FIX 10 ( ) realtime_stream MT4_WRITER.update_candle.
 Asset.write WriterThread MT4_WRITER
 .
 """
    def __init__(self):
        super().__init__(daemon=True, name="WriterThread")
        self.running = True
    def run(self):
        while self.running:
            try:
                now = time.time()
                dirty_count = 0
                for asset in ALL_STREAMING_ASSETS:
                    # ===== FIX 11: MT4_WRITER =====
                    # ( — )
                    if asset.symbol in MT4_WRITER.sync_state:
                        # Still update web store even for MT4_WRITER-managed assets
                        try:
                            _web_update_asset(asset, full_resync=True)
                        except Exception:
                            pass
                        continue
                    if asset.dirty and (now - asset.last_write >= WRITE_INTERVAL):
                        if asset.write():
                            dirty_count += 1
                            # Update web dashboard candle store
                            try:
                                _web_update_asset(asset, full_resync=True)
                            except Exception:
                                pass
                if dirty_count > 0: refresh_mt4()
                time.sleep(0.1)
            except Exception as e:
                logmsg(f"[WriterThread] loop error: {e}")
                time.sleep(0.5)

writer_thread = WriterThread()
writer_thread.start()

async def connect_quotex(email, password, force_fresh=False, max_attempts=3):
    global CLIENT, CONNECTION_ALIVE, EMAIL, PASSWORD
    EMAIL, PASSWORD = email, password
    for attempt in range(1, max_attempts + 1):
        try:
            if CLIENT:
                try:
                    close_task = asyncio.create_task(CLIENT.close())
                    await asyncio.wait([close_task], timeout=3.0)
                except Exception: pass
                finally: CLIENT = None
            await asyncio.sleep(0.3)
            if force_fresh or attempt > 1:
                session_manager.delete_session_file()
                session_manager.delete_browser_dir()
            # FIX K: QX_HOST ( )
            CLIENT = Quotex(email=email, password=password, host=QX_HOST, lang="en")
            with suppress_terminal_output():
                check, reason = await CLIENT.connect()
            if check:
                try:
                    await CLIENT.change_account("PRACTICE")
                    await asyncio.sleep(0.5)
                except Exception: pass
                try: await CLIENT.get_all_assets()
                except Exception: pass
                CONNECTION_ALIVE = True
                # FIX K:
                session_manager.record_success(email, host=QX_HOST)
                return True
            else:
                error_msg = str(reason) if reason else "Unknown error"
                session_manager.record_failure(error_msg)
        except Exception as e:
            error_msg = str(e)[:200]
            session_manager.record_failure(error_msg)
            if attempt < max_attempts: await asyncio.sleep(5 * attempt)
    CONNECTION_ALIVE = False
    return False

async def keepalive_loop():
    # ===== FIX 7: keepalive (5s) + =====
    # : " ".
    # : keepalive_loop
    # `await asyncio.sleep(KEEPALIVE_PING_INTERVAL)` .
    # : `asyncio.sleep` (0.5s) .
    # keepalive .
    tick_count = 0
    last_ping_at = 0.0
    while True:
        await asyncio.sleep(0.5)  # 500ms ()
        now = time.time()
        # : ping
        if now - last_ping_at < KEEPALIVE_PING_INTERVAL:
            continue
        last_ping_at = now
        if not CONNECTION_ALIVE or CLIENT is None or CLIENT.api is None: continue
        try:
            # 1) engine.io ping ( Socket.IO EIO=3) —
            CLIENT.api.send_websocket_request("2", no_force_send=False)
            # 2) application-level tick —
            CLIENT.api.send_websocket_request('42["tick"]', no_force_send=False)
            # 3)
            if tick_count % 3 == 0:
                CLIENT.api.send_websocket_request('42["instruments/get"]', no_force_send=False)
            tick_count += 1
        except Exception:
            pass


async def stale_message_watchdog():
    # ===== FIX: watchdog + =====
    # WS STALE_MESSAGE_TIMEOUT (45s)
    # .
    # latency ~25s <5s.
    # FIX B: auto_reconnect
    # (> ) —
    # .
    global CONNECTION_ALIVE, LAST_CONNECTION_DROP_TIME
    while True:
        await asyncio.sleep(STALE_WATCHDOG_INTERVAL)
        if not CONNECTION_ALIVE or CLIENT is None or CLIENT.api is None:
            continue
        try:
            silent_for = time.time() - CLIENT.api.last_message_at
            if silent_for > STALE_MESSAGE_TIMEOUT:
                logmsg(
                    f"[stale_watchdog] no messages for {silent_for:.1f}s "
                    f"(>{STALE_MESSAGE_TIMEOUT}s); recycling connection."
                )
                # ===== FIX B: =====
                # LONG_DISCONNECT_THRESHOLD (1h)
                # .
                if LAST_CONNECTION_DROP_TIME == 0:
                    LAST_CONNECTION_DROP_TIME = time.time()
                    logmsg(f"[stale_watchdog] drop time recorded at {LAST_CONNECTION_DROP_TIME:.0f}")
                CONNECTION_ALIVE = False
                # WS close frame on_close
                try:
                    if CLIENT.api.websocket_client and CLIENT.api.websocket_client.wss:
                        CLIENT.api.websocket_client.wss.close()
                except Exception:
                    pass
                # auto_reconnect
        except Exception as e:
            logmsg(f"[stale_watchdog] error: {e}")

async def health_monitor():
    global LAST_HEALTH_CHECK, CONNECTION_ALIVE
    consecutive_dead_checks = 0
    while True:
        await asyncio.sleep(HEALTH_CHECK_INTERVAL)
        now = time.time()
        LAST_HEALTH_CHECK = now
        if not CONNECTION_ALIVE or CLIENT is None:
            consecutive_dead_checks = 0
            continue
        is_dead = False
        dead_reason = ""
        stale_count = sum(1 for a in ALL_STREAMING_ASSETS if a.updates > 0 and (now - a.last_update_time) > STALE_DATA_TIMEOUT)
        if stale_count > len(ALL_STREAMING_ASSETS) * STALE_RATIO_TRIGGER:
            is_dead = True
            dead_reason = f"stale ratio {stale_count}/{len(ALL_STREAMING_ASSETS)} exceeded {STALE_RATIO_TRIGGER}"
        if is_dead:
            logmsg(f"[health_monitor] marking connection DEAD: {dead_reason}")
            CONNECTION_ALIVE = False
            consecutive_dead_checks = 0

async def auto_reconnect():
    # ===== FIX B: + =====
    # : " ".
    # ( stale_message_watchdog )
    # LONG_DISCONNECT_THRESHOLD (1h).
    # 1000 .
    # FIX K: QX_HOST
    global CLIENT, CONNECTION_ALIVE, RECONNECTING, LAST_CONNECTION_DROP_TIME, QX_HOST
    consecutive_failures = 0
    while True:
        await asyncio.sleep(RECONNECT_CHECK_INTERVAL)
        # ===== FIX B: ( ) =====
        # stale_message_watchdog
        # (on_close on_error connect_quotex ).
        # .
        if not CONNECTION_ALIVE and LAST_CONNECTION_DROP_TIME == 0:
            LAST_CONNECTION_DROP_TIME = time.time()
            logmsg(f"[reconnect] connection loss detected at {LAST_CONNECTION_DROP_TIME:.0f}; "
                   f"will re-fetch all candles if outage exceeds {LONG_DISCONNECT_THRESHOLD}s")
        if CONNECTION_ALIVE or RECONNECTING:
            consecutive_failures = 0
            continue
        RECONNECTING = True
        try:
            email = session_manager.get_saved_email()
            # ===== FIX: try RECONNECTING =====
            # : `if not (email and PASSWORD): continue`
            # => try RECONNECTING = True =>
            # => !
            if not (email and PASSWORD):
                # RECONNECTING
                RECONNECTING = False
                continue
            delay = 0 if consecutive_failures == 0 else min(RECONNECT_BASE_DELAY * (2 ** (consecutive_failures - 1)), RECONNECT_MAX_DELAY)
            if delay > 0:
                logmsg(f"[reconnect] connection lost, retrying in {delay:.0f}s...")
                await asyncio.sleep(delay)
            else:
                logmsg("[reconnect] connection lost, reconnecting immediately...")
            # FIX K:
            _saved_host = session_manager.get_saved_host()
            if _saved_host and QX_HOST != _saved_host:
                QX_HOST = _saved_host
                logmsg(f"[reconnect] using saved host: {QX_HOST}")
            success = await connect_quotex(email, PASSWORD, force_fresh=True, max_attempts=1)
            if success:
                logmsg("[reconnect] reconnect successful, restarting streams...")
                consecutive_failures = 0
                # ===== FIX 7: auto-throttle ( ) =====
                # ===== FIX: last_message_at =====
                # stale_watchdog .
                if CLIENT is not None and CLIENT.api is not None:
                    CLIENT.api.last_message_at = time.time()
                # ===== FIX B: =====
                drop_duration = 0.0
                should_refetch_all = False
                if LAST_CONNECTION_DROP_TIME > 0:
                    drop_duration = time.time() - LAST_CONNECTION_DROP_TIME
                    if drop_duration > LONG_DISCONNECT_THRESHOLD:
                        should_refetch_all = True
                        logmsg(
                            f"[reconnect] LONG disconnect detected: {drop_duration/60:.1f} min "
                            f"> {LONG_DISCONNECT_THRESHOLD/60:.0f} min threshold — "
                            f"will re-fetch ALL candles from scratch"
                        )

                LAST_CONNECTION_DROP_TIME = 0
                if should_refetch_all:
                    # streams
                    try:
                        asyncio.run_coroutine_threadsafe(refetch_all_candles(), ASYNC_LOOP)
                    except Exception as e:
                        logmsg(f"[reconnect] failed to schedule full re-fetch: {e}")
                        # fallback: streams
                        for asset in ALL_STREAMING_ASSETS:
                            try:
                                if asset.stream_task and not asset.stream_task.done():
                                    asset.stream_task.cancel()
                                asset.streaming = False
                                asset.stream_task = asyncio.run_coroutine_threadsafe(subsecond_stream(asset) if IS_SUBSECOND else realtime_stream(asset), ASYNC_LOOP)
                                await asyncio.sleep(0.05)
                            except Exception as e2:
                                logmsg(f"[reconnect] failed to restart stream for {asset.symbol}: {e2}")
                else:
                    # (< ) — streams
                    if drop_duration > 0:
                        logmsg(f"[reconnect] short disconnect ({drop_duration:.1f}s) — restarting streams only")
                    for asset in ALL_STREAMING_ASSETS:
                        try:
                            if asset.stream_task and not asset.stream_task.done():
                                asset.stream_task.cancel()
                            asset.streaming = False
                            asset.stream_task = asyncio.run_coroutine_threadsafe(subsecond_stream(asset) if IS_SUBSECOND else realtime_stream(asset), ASYNC_LOOP)
                            await asyncio.sleep(0.05)
                        except Exception as e:
                            logmsg(f"[reconnect] failed to restart stream for {asset.symbol}: {e}")
            else:
                consecutive_failures += 1
        except Exception as e:
            logmsg(f"[reconnect] unexpected error: {e}")
            consecutive_failures += 1
        finally:
            RECONNECTING = False

def _make_progress_printer(symbol: str, start_ts: float, idx: int, total: int):
    display = pretty_asset_name(symbol)
    def on_progress(current, total, label=None, worker_label=None):
        total = total or FETCH_DURATION_SECONDS
        pct = min(current / total, 1.0) if total > 0 else 0
        bar_len = 20
        filled = int(bar_len * pct)
        bar = "#" * filled + "-" * (bar_len - filled)
        elapsed = time.time() - start_ts
        print(f"\r  {display:<25} [{bar}] {pct*100:4.1f}% {elapsed:>2.0f}s", end="", flush=True)
    return on_progress

async def fetch_candles_once(asset: Asset, idx=1, total=1):
    api_name = asset.api_symbol
    display_name = asset.symbol
    candles = []
    # Sub-minute timeframes: fetch period=1 (1s candles) then aggregate locally
    is_sub_minute = PERIOD_SECONDS < 60
    fetch_period = 1 if is_sub_minute else PERIOD_SECONDS
    if is_sub_minute:
        # Use get_candles (single request) — more reliable for period=1
        # Make staggered requests going backwards in time
        try:
            on_progress = _make_progress_printer(display_name, time.time(), idx, total)
            try: on_progress(FETCH_DURATION_SECONDS, FETCH_DURATION_SECONDS)
            except Exception: pass
            # الهدف: نحاول جلب ما يكفي لـ INITIAL_CANDLES شموع مجمّعة
            # INITIAL_CANDLES * PERIOD_SECONDS = عدد شموع 1s المطلوبة
            # هامش 1.5x (بدل 2x) لتقليل وقت الجلب وبالتالي تقليل الفجوة الزمنية
            # الفجوة الكبيرة = شموع مفقودة أكثر بين التاريخي والبث المباشر
            target_1s_count = int(INITIAL_CANDLES * PERIOD_SECONDS * 1.5)
            chunk_seconds = 500  # ~500 1s candles per request (server limit)
            all_candles_1s = []
            current_end = time.time()
            # زيادة max_chunks من 20 → 40 لضمان جلب كافٍ حتى للأصول البطيئة
            max_chunks = 40
            chunks_done = 0
            # تتبع الـ chunks الفارغة المتتالية (للإيقاف المبكر الذكي)
            empty_chunks_in_a_row = 0
            while len(all_candles_1s) < target_1s_count and chunks_done < max_chunks:
                chunk_end = current_end - (chunks_done * chunk_seconds)
                try:
                    res_chunk = await asyncio.wait_for(
                        CLIENT.get_candles(api_name, chunk_end, chunk_seconds, fetch_period),
                        timeout=20,
                    )
                except Exception as e:
                    if chunks_done == 0:
                        logmsg(f"[fetch:{display_name}] get_candles(period=1) chunk {chunks_done+1} failed: {e}")
                    # retry once on transient error
                    if empty_chunks_in_a_row < 2:
                        empty_chunks_in_a_row += 1
                        await asyncio.sleep(0.2)
                        continue
                    break
                if not res_chunk or len(res_chunk) == 0:
                    empty_chunks_in_a_row += 1
                    # 3 chunks فارغة متتالية = نهاية التاريخ المتاح → توقف
                    if empty_chunks_in_a_row >= 3:
                        break
                    chunks_done += 1
                    continue
                # عتبة إيقاف أقل صرامة (من 50 → 10): بعض الأصول تُرجع 20-30 شمعة فقط في نهاية الأسبوع
                # هذا طبيعي ولا يعني أننا وصلنا لنهاية التاريخ
                if len(res_chunk) < 10 and chunks_done > 0:
                    all_candles_1s.extend(res_chunk)
                    break
                empty_chunks_in_a_row = 0
                all_candles_1s.extend(res_chunk)
                chunks_done += 1
                try:
                    pct = min(len(all_candles_1s) / target_1s_count, 1.0)
                    on_progress(pct * FETCH_DURATION_SECONDS, FETCH_DURATION_SECONDS)
                except Exception:
                    pass
                # delay صغير (0.03 بدل 0.05) لتسريع الجلب
                await asyncio.sleep(0.03)
            # De-duplicate by time
            seen_ts = set()
            unique_1s = []
            for c in all_candles_1s:
                if isinstance(c, dict):
                    ts = int(float(c.get('time', c.get('timestamp', 0))))
                    if ts not in seen_ts:
                        seen_ts.add(ts)
                        unique_1s.append(c)
            candles = unique_1s
            # No log message here — fetch_candles_with_retry prints the final count
        except Exception as e:
            print()
            logmsg(f"[fetch:{display_name}] get_candles(period=1) failed: {e}")
    else:
        # 60s+ timeframe — use parallel get_historical_candles
        if hasattr(CLIENT, 'get_historical_candles'):
            try:
                on_progress = _make_progress_printer(display_name, time.time(), idx, total)
                res = await asyncio.wait_for(
                    CLIENT.get_historical_candles(
                        api_name,
                        amount_of_seconds=FETCH_DURATION_SECONDS,
                        period=PERIOD_SECONDS,
                        max_workers=FETCH_MAX_WORKERS,
                        progress_callback=on_progress
                    ),
                    timeout=60,
                )
                if res and len(res) > 0: candles = res
            except Exception as e:
                print()
                logmsg(f"[fetch:{display_name}] get_historical_candles failed: {e}")
    if candles:
        formatted = []
        for c in candles:
            if not isinstance(c, dict): continue
            try:
                ts = int(float(c.get("time", c.get("timestamp", 0))))
                # Align to fetch_period (1s for sub-minute, PERIOD_SECONDS otherwise)
                aligned = _align_time(ts, period_seconds=fetch_period)
                o, h, l, cl = float(c.get("open", 0)), float(c.get("high", c.get("max", 0))), float(c.get("low", c.get("min", 0))), float(c.get("close", 0))
                if o > 0 and h > 0 and l > 0 and cl > 0:
                    formatted.append({'time': aligned, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': random.randint(50, 200)})
            except Exception: continue
        # Aggregate 1s candles into target subsecond timeframe
        if is_sub_minute and formatted:
            formatted = _aggregate_sub_minute(formatted, PERIOD_SECONDS)
        seen, unique = set(), []
        for c in formatted:
            if c['time'] not in seen:
                seen.add(c['time'])
                unique.append(c)
        unique.sort(key=lambda x: x['time'])
        return unique[-INITIAL_CANDLES:]
    return []


# ==============================================================================
# ===== BRIDGE FETCH HELPER (سد فجوة الشموع الأخيرة بين التاريخي والبث) =====
# ==============================================================================
# هذه الدالة المستقلة تُحاكي أسلوب كود 199 الشموع الذي يعمل بدون ثغرات:
#   1) طلب واحد (وليس متوازي) عبر CLIENT.get_candles
#   2) ينتهي عند time.time() الحالي (وليس T0 عند بداية الجلب التاريخي)
#   3) يستقبل آخر BRIDGE_FETCH_CANDLES شموع بما فيها الشمعة الحالية المتشكلة
#   4) يدمجها مع الشموع التاريخية (الشمعة الجسرية تستبدل التاريخية في نفس الفترة)
#
# الأمان:
#   - إذا فشلت لأي سبب، تُرجع existing_candles كما هي دون أي تغيير
#   - لا تُكسر أبداً سير عمل fetch_candles_with_retry
#   - تُحترم BRIDGE_FETCH_ENABLED=False (يمكن تعطيلها فوراً)
#   - تستخدم Semaphore لمنع إرهاق الخادم بطلبات متزامنة
# ==============================================================================
async def _bridge_fetch_recent_candles(asset: Asset, existing_candles: list) -> list:
    """جلب جسري لآخر BRIDGE_FETCH_CANDLES شمعة لسد فجوة 4-5 شموع.

    Args:
        asset: كائن Asset
        existing_candles: قائمة الشموع التاريخية المُجلبَة مسبقاً

    Returns:
        قائمة مدمجة (تاريخي + جسري) مرتبة ومُزالة التكرار، أو existing_candles
        كما هي عند فشل الجلب (الأمان: لا تُكسر العملية أبداً).
    """
    # ── فحوصات الأمان الأولية ─────────────────────────────────────────────
    if not BRIDGE_FETCH_ENABLED:
        return existing_candles
    if not existing_candles or len(existing_candles) == 0:
        return existing_candles
    if CLIENT is None or CLIENT.api is None:
        return existing_candles
    if not getattr(getattr(CLIENT, 'api', None), 'state', None):
        return existing_candles
    if not getattr(CLIENT.api.state, 'check_accepted_connection', False):
        return existing_candles

    # ── إنشاء Semaphore بأمان (lazy init على الـ loop الحالي) ──────────────
    global _BRIDGE_FETCH_SEMAPHORE
    if _BRIDGE_FETCH_SEMAPHORE is None:
        try:
            _BRIDGE_FETCH_SEMAPHORE = asyncio.Semaphore(BRIDGE_FETCH_SEMAPHORE_LIMIT)
        except RuntimeError:
            # الـ loop غير جاهز — تُرجع existing_candles دون كسر العمل
            return existing_candles

    try:
        async with _BRIDGE_FETCH_SEMAPHORE:
            is_sub_minute = PERIOD_SECONDS < 60
            # ✨ السر: استخدم time.time() الحالي (وليس T0 عند بداية الجلب التاريخي)
            bridge_end_time = int(time.time())
            bridge_candles = []

            if is_sub_minute:
                # ── للثواني الفرعية: جلب 1s ثم تجميع محلياً ──────────────────
                # هامش 5x لضمان تغطية كاملة للفجوة الزمنية الكبيرة المحتملة
                # (BRIDGE_FETCH_CANDLES=15 × PERIOD_SECONDS=5 × 5 = 375 ثانية من شموع 1s)
                # هذا يضمن أن الجسر يغطي 75 شمعة 5s — أكثر من كافٍ لأي فجوة
                bridge_1s_offset = BRIDGE_FETCH_CANDLES * PERIOD_SECONDS * 5
                try:
                    bridge_1s = await asyncio.wait_for(
                        CLIENT.get_candles(
                            asset.api_symbol,
                            bridge_end_time,
                            bridge_1s_offset,
                            1  # period=1 (1s candles — مدعوم دائماً من الخادم)
                        ),
                        timeout=BRIDGE_FETCH_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    logmsg(f"[bridge:{asset.symbol}] 1s fetch timeout (non-fatal)")
                    return existing_candles
                except Exception as e:
                    logmsg(f"[bridge:{asset.symbol}] 1s fetch failed (non-fatal): {e}")
                    return existing_candles

                if not bridge_1s:
                    return existing_candles

                # تنسيق شموع 1s
                bridge_formatted = []
                for c in bridge_1s:
                    if not isinstance(c, dict):
                        continue
                    try:
                        ts = int(float(c.get("time", c.get("timestamp", 0))))
                        aligned = _align_time(ts, period_seconds=1)
                        o = float(c.get("open", 0) or 0)
                        h = float(c.get("high", c.get("max", 0)) or 0)
                        l = float(c.get("low", c.get("min", 0)) or 0)
                        cl = float(c.get("close", c.get("c", 0)) or 0)
                        if o > 0 and h > 0 and l > 0 and cl > 0:
                            bridge_formatted.append({
                                'time': aligned, 'open': o, 'high': h,
                                'low': l, 'close': cl, 'volume': 1
                            })
                    except Exception:
                        continue

                # تجميع الـ 1s إلى الإطار الزمني المطلوب (5s/10s/15s/30s)
                bridge_candles = _aggregate_sub_minute(bridge_formatted, PERIOD_SECONDS)
            else:
                # ── لإطارات 60s+: استخدام _fetch_historical_batch مباشرة ──
                # لماذا؟ get_candles تُعيد subscribe للـ WebSocket مما يتعارض مع
                # realtime_stream الذي يعمل في الخلفية. _fetch_historical_batch
                # يستخدم event_name فريد (مع index) ولا يُعيد subscribe.
                # هذا يحل مشكلة "الفجوة عادت في M1+".
                bridge_offset = PERIOD_SECONDS * BRIDGE_FETCH_CANDLES
                # index فريد لتجنب التعارض مع get_historical_candles السابق
                _bridge_index = next(_request_counter)
                try:
                    bridge_raw = await asyncio.wait_for(
                        CLIENT._fetch_historical_batch(
                            asset.api_symbol,
                            bridge_end_time,
                            bridge_offset,
                            PERIOD_SECONDS,
                            _bridge_index,
                            BRIDGE_FETCH_TIMEOUT
                        ),
                        timeout=BRIDGE_FETCH_TIMEOUT + 5,  # هامش 5s إضافي
                    )
                except asyncio.TimeoutError:
                    logmsg(f"[bridge:{asset.symbol}] fetch timeout (non-fatal)")
                    return existing_candles
                except Exception as e:
                    logmsg(f"[bridge:{asset.symbol}] fetch failed (non-fatal): {e}")
                    return existing_candles

                if not bridge_raw:
                    return existing_candles

                # تحويل النتيجة عبر _parse_historical_candles (نفس آلية get_historical_candles)
                try:
                    bridge_parsed = CLIENT._parse_historical_candles(bridge_raw)
                except Exception:
                    bridge_parsed = []

                if not bridge_parsed:
                    return existing_candles

                # تنسيق شموع الجسر
                for c in bridge_parsed:
                    if not isinstance(c, dict):
                        continue
                    try:
                        ts = int(c.get("time", c.get("timestamp", 0)))
                        aligned = _align_time(ts, period_seconds=PERIOD_SECONDS)
                        o = float(c.get("open", 0) or 0)
                        h = float(c.get("high", 0) or 0)
                        l = float(c.get("low", 0) or 0)
                        cl = float(c.get("close", 0) or 0)
                        if o > 0 and h > 0 and l > 0 and cl > 0:
                            bridge_candles.append({
                                'time': aligned, 'open': o, 'high': h,
                                'low': l, 'close': cl, 'volume': 1
                            })
                    except Exception:
                        continue

            if not bridge_candles:
                return existing_candles

            # ── الدمج الآمن: الجسر يستبدل التاريخي في نفس الفترة الزمنية ───
            # (الشموع الجسرية أحدث وأدق، خاصة للشموع الأخيرة غير المكتملة)
            bridge_by_time = {c['time']: c for c in bridge_candles}
            merged_list = []
            for c in existing_candles:
                if c['time'] in bridge_by_time:
                    # استبدل الشمعة التاريخية بالجسرية الأحدث
                    merged_list.append(bridge_by_time.pop(c['time']))
                else:
                    merged_list.append(c)
            # أضف الشموع الجسرية المتبقية (جديدة، غير موجودة في التاريخي)
            merged_list.extend(bridge_by_time.values())

            # ── الترتيب وإزالة التكرار ─────────────────────────────────────
            seen = set()
            unique = []
            for c in sorted(merged_list, key=lambda x: x['time']):
                if c['time'] not in seen:
                    seen.add(c['time'])
                    unique.append(c)

            # قص إلى INITIAL_CANDLES (نفس سلوك الكود الأصلي)
            result = unique[-INITIAL_CANDLES:]

            # تسجيل بسيط (فقط إذا تم إضافة شموع جديدة فعلية)
            added = len(result) - len(existing_candles)
            if added > 0:
                logmsg(f"[bridge:{asset.symbol}] +{added} new candles bridged (total {len(result)})")

            return result

    except Exception as e:
        # ── الأمان النهائي: لا تُكسر الجلب التاريخي أبداً ──────────────────
        try:
            logmsg(f"[bridge:{asset.symbol}] bridge fetch error (non-fatal): {e}")
        except Exception:
            pass
        return existing_candles


async def fetch_candles_with_retry(asset: Asset, max_retries=3, idx=1, total=1):
    # For sub-minute, use lower threshold + 1 retry (server caps ~500-1000 1s candles)
    is_sub_minute = PERIOD_SECONDS < 60
    threshold = 20 if is_sub_minute else MIN_CANDLES_THRESHOLD
    max_retries = 1 if is_sub_minute else MAX_FETCH_RETRIES
    last_error = None
    for attempt in range(1, max_retries + 1):

        if not CONNECTION_ALIVE or CLIENT is None or CLIENT.api is None:
            logmsg(f"[fetch_retry:{asset.symbol}] connection dead before attempt {attempt}; waiting for reconnect...")
            # (timeout 15s)
            try:
                await wait_until(
                    lambda: CONNECTION_ALIVE and CLIENT is not None and CLIENT.api is not None,
                    timeout=15.0,
                    poll_interval=0.5,
                )
            except asyncio.TimeoutError:
                logmsg(f"[fetch_retry:{asset.symbol}] reconnect did not happen within 15s; giving up on this asset")
                return 0, attempt
        try:
            candles = await fetch_candles_once(asset, idx, total)
        except Exception as e:
            candles = []
            last_error = e
            logmsg(f"[fetch_retry:{asset.symbol}] attempt {attempt}/{max_retries} raised: {e}")
        # ===== BRIDGE FETCH: سد فجوة 4-5 شموع بين التاريخي والبث المباشر =====
        # استدعاء آمن: أي خطأ يُرجع candles كما هي دون كسر العملية.
        # يُجرّب آخر BRIDGE_FETCH_CANDLES شمعة تنتهي عند time.time() الحالي.
        if candles and len(candles) > 0:
            try:
                candles = await _bridge_fetch_recent_candles(asset, candles)
            except Exception as bridge_err:
                # الأمان التام: لا تُكسر الجلب التاريخي أبداً
                logmsg(f"[fetch_retry:{asset.symbol}] bridge skipped (non-fatal): {bridge_err}")
        if len(candles) >= threshold:
            # Merge historical candles with any live ticks collected during fetch
            # (realtime_stream may have appended live candles to asset.candles)
            live_candles = []
            if asset.candles:
                hist_times = set(c['time'] for c in candles)
                for c in asset.candles:
                    if c['time'] not in hist_times and c['time'] > (candles[-1]['time'] if candles else 0):
                        live_candles.append(c)
            asset.candles = candles + live_candles
            if asset.candles: asset.price = asset.candles[-1]['close']
            asset.write(force=True)
            # Update MT4_WRITER.sync_state with the full historical + live candles
            # so update_candle doesn't overwrite HST with only the few live candles
            MT4_WRITER.sync_state[asset.symbol] = {
                'period': PERIOD,
                'candles': list(asset.candles),
                'last_write': 0,
                'last_price': float(asset.candles[-1]['close']) if asset.candles else 0.0,
            }
            return len(asset.candles), attempt

        # Merge even for low counts
        live_candles = []
        if asset.candles:
            hist_times = set(c['time'] for c in candles)
            for c in asset.candles:
                if c['time'] not in hist_times and c['time'] > (candles[-1]['time'] if candles else 0):
                    live_candles.append(c)
        asset.candles = candles + live_candles
        if asset.candles: asset.price = asset.candles[-1]['close']
        asset.write(force=True)
        # Update sync_state even for low counts
        if asset.candles:
            MT4_WRITER.sync_state[asset.symbol] = {
                'period': PERIOD,
                'candles': list(asset.candles),
                'last_write': 0,
                'last_price': float(asset.candles[-1]['close']) if asset.candles else 0.0,
            }
        # ===== FIX 3: exponential backoff retries =====
        if attempt < max_retries:
            delay = min(RETRY_BACKOFF_BASE * (2 ** (attempt - 1)), RETRY_BACKOFF_MAX)
            logmsg(f"[fetch_retry:{asset.symbol}] attempt {attempt}/{max_retries} got {len(candles)} candles; retry in {delay:.1f}s")
            await asyncio.sleep(delay)
    if last_error:
        logmsg(f"[fetch_retry:{asset.symbol}] all {max_retries} attempts failed. Last error: {last_error}")
    return len(candles), max_retries


# ==============================================================================
# SUBSECOND STREAM — separate system for 5s/10s/15s/30s timeframes
# Does NOT use fetch_candles_with_retry, MT4_WRITER.update_candle, or mt4_gap_filler.
# Aggregates realtime ticks into subsecond candles and writes HST directly.
# ==============================================================================

def _subsecond_align(ts: int) -> int:
    """Align timestamp to subsecond window boundary (with TZ offset for consistency)."""
    tz = _get_tz_offset()
    return ((int(ts) + tz) // SUBSECOND_SECONDS) * SUBSECOND_SECONDS

def _subsecond_write_hst(asset_symbol: str, candles: list):
    """Write subsecond HST file. Period field = 1 (MT4 minimum).
    Filename: {asset_symbol}1.hst (e.g., AUDUSD-5S-OTC1.hst)
    """
    if not candles:
        return
    file_name = f"{asset_symbol}1.hst"
    file_path = os.path.join(MT4_HISTORY_PATH, file_name)
    temp_path = file_path + '.tmp'
    try:
        os.makedirs(MT4_HISTORY_PATH, exist_ok=True)
    except Exception:
        pass
    try:
        header = bytearray(148)
        struct.pack_into('<I', header, 0, 400)
        struct.pack_into('64s', header, 4, b'MetaQuotes Software Corp.'.ljust(64, b'\x00'))
        struct.pack_into('12s', header, 68, asset_symbol[:12].encode('ascii').ljust(12, b'\x00'))
        struct.pack_into('<I', header, 80, 1)  # period = 1 (M1, MT4 minimum)
        first_price = candles[0]['close'] if candles else 0.0
        digits = _resolve_digits(asset_symbol, first_price)
        struct.pack_into('<I', header, 84, digits)
        struct.pack_into('<I', header, 88, 0)
        struct.pack_into('<I', header, 92, 0)
        body_size = len(candles) * 44
        buffer = bytearray(148 + body_size)
        buffer[:148] = header
        offset = 148
        for c in candles:
            struct.pack_into('<I', buffer, offset, int(c['time']))
            struct.pack_into('<d', buffer, offset + 4, float(c['open']))
            struct.pack_into('<d', buffer, offset + 12, float(c['low']))
            struct.pack_into('<d', buffer, offset + 20, float(c['high']))
            struct.pack_into('<d', buffer, offset + 28, float(c['close']))
            struct.pack_into('<Q', buffer, offset + 36, int(c.get('volume', 0)))
            offset += 44
        with open(temp_path, 'wb') as f:
            f.write(buffer)
        # atomic replace with retry
        replaced = False
        for attempt in range(5):
            try:
                os.replace(temp_path, file_path)
                replaced = True
                break
            except (PermissionError, OSError):
                time.sleep(0.05)
                continue
        if not replaced:
            try:
                with open(file_path, 'wb') as f:
                    f.write(buffer)
            except Exception:
                pass
    except Exception:
        pass
    finally:
        if os.path.exists(temp_path):
            try: os.remove(temp_path)
            except Exception: pass

async def fetch_subsecond_history(
    asset: Asset,
    idx: int = 1,
    total: int = 1,
    subsecond_seconds: int = None,
    target_candles: int = None,
    label: str = None,
):
    """Fetch historical subsecond candles by fetching 1s candles and aggregating.

    Strategy (per Quotex server limitations):
    1. Use `get_candles` (single request, NOT parallel get_historical_candles)
       with period=1 -- server returns ~500 1s candles per request
    2. Make multiple staggered requests going backwards in time
    3. Stop when server returns 3 empty chunks in a row (hit history limit)
    4. Aggregate 1s candles locally into 5s/10s/15s/30s

    v8.4: added optional parameters subsecond_seconds/target_candles/label.
    They fall back to SUBSECOND_SECONDS / SUBSECOND_HISTORY_CANDLES / SUBSECOND_LABEL
    when None. This lets M1 mode call us with subsecond_seconds=5 even when
    IS_SUBSECOND is False.

    Uses a semaphore (3 concurrent) to avoid overwhelming server.
    """
    if CLIENT is None or not hasattr(CLIENT, 'get_candles'):
        logmsg(f"[subfetch:{asset.symbol}] CLIENT not ready")
        return []
    api_name = asset.api_symbol
    display_name = asset.symbol
    # v8.4: resolve optional parameters -- fall back to globals if not provided
    _sec = subsecond_seconds if subsecond_seconds is not None else SUBSECOND_SECONDS
    _target = target_candles if target_candles is not None else SUBSECOND_HISTORY_CANDLES
    _label = label if label is not None else (SUBSECOND_LABEL or f"{_sec}S")
    if _sec is None or _sec <= 0:
        logmsg(f"[subfetch:{display_name}] invalid subsecond_seconds={_sec}")
        return []
    # Target: target_candles aggregated candles
    # = target_candles * subsecond_seconds 1s candles (with SUBSECOND_FETCH_MARGIN margin)
    # v8.3: use SUBSECOND_FETCH_MARGIN (1.3x) -- was hardcoded 1.5x in v8.0, 2.0x in v8.1
    target_1s_count = int(_target * _sec * SUBSECOND_FETCH_MARGIN)
    chunk_seconds = 500  # ~500 1s candles per request (server limit)
    all_candles_1s = []
    current_end = time.time()
    # v8.3: use SUBSECOND_MAX_CHUNKS (5) -- was 40 in v8.0, 60 in v8.1, now 5
    max_chunks = SUBSECOND_MAX_CHUNKS
    chunks_done = 0
    empty_chunks_in_a_row = 0
    # Semaphore (3 concurrent fetches, not 41) — created lazily on the running loop
    global _SUBSECOND_FETCH_SEMAPHORE
    if _SUBSECOND_FETCH_SEMAPHORE is None:
        _SUBSECOND_FETCH_SEMAPHORE = asyncio.Semaphore(3)
    async with _SUBSECOND_FETCH_SEMAPHORE:
        logmsg(f"[subfetch:{display_name}] start: get_candles(period=1), target ~{target_1s_count} 1s candles")
        try:
            while len(all_candles_1s) < target_1s_count and chunks_done < max_chunks:
                if not CLIENT or not CLIENT.api or not getattr(CLIENT.api.state, 'check_accepted_connection', False):
                    logmsg(f"[subfetch:{display_name}] connection lost during fetch")
                    break
                chunk_end = current_end - (chunks_done * chunk_seconds)
                try:
                    res_chunk = await asyncio.wait_for(
                        CLIENT.get_candles(api_name, chunk_end, chunk_seconds, 1),
                        timeout=20,
                    )
                except Exception as e:
                    if chunks_done == 0:
                        logmsg(f"[subfetch:{display_name}] get_candles(period=1) chunk {chunks_done+1} failed: {e}")
                    # retry on transient error
                    if empty_chunks_in_a_row < 2:
                        empty_chunks_in_a_row += 1
                        await asyncio.sleep(0.2)
                        continue
                    break
                if not res_chunk or len(res_chunk) == 0:
                    empty_chunks_in_a_row += 1
                    # 3 chunks فارغة متتالية = نهاية التاريخ المتاح
                    if empty_chunks_in_a_row >= 3:
                        break
                    chunks_done += 1
                    continue
                # عتبة إيقاف أقل صرامة (من 50 → 10)
                if len(res_chunk) < 10 and chunks_done > 0:
                    all_candles_1s.extend(res_chunk)
                    break
                empty_chunks_in_a_row = 0
                all_candles_1s.extend(res_chunk)
                chunks_done += 1
                # v8.3: bigger inter-chunk delay (0.03 -> 0.15s) -- the server was
                # throttling us after a few assets because we hammered it at 30 req/s.
                await asyncio.sleep(0.15)
                # v8.3/v8.6: user explicitly asked: if we already have enough 1s
                # candles to cover >=425 seconds of data (the original "85 5s
                # candles" threshold = 425 seconds), stop fetching more chunks.
                # v8.6: made TIME-BASED so the threshold scales correctly for any
                # _sec value. For 5s mode: 425s/5 = 85 (matches the original
                # SUBSECOND_EARLY_EXIT_CANDLES). For 1s mode: 425s/1 = 425
                # 1s candles, which is the right scale (1 chunk yields ~700 1s
                # candles = ~12 1m candles, plenty for the M1 bridge).
                _projected = len(all_candles_1s) // max(1, _sec)
                _time_based_threshold = max(1, 425 // max(1, _sec))
                if chunks_done >= 1 and _projected >= _time_based_threshold:
                    logmsg(
                        f"[subfetch:{display_name}] early-exit: {_projected} projected {_label} candles "
                        f">= {_time_based_threshold} threshold ({425}s of data); stopping chunk requests"
                    )
                    break
        except Exception as e:
            logmsg(f"[subfetch:{display_name}] FAILED: {e}")
            return []
    # De-duplicate by time (chunks may overlap)
    seen_ts = set()
    unique_1s = []
    for c in all_candles_1s:
        if isinstance(c, dict):
            ts = int(float(c.get('time', c.get('timestamp', 0))))
            if ts not in seen_ts:
                seen_ts.add(ts)
                unique_1s.append(c)
    logmsg(f"[subfetch:{display_name}] got {len(unique_1s)} 1s candles from {chunks_done} chunks, aggregating to {_label}")
    # Format 1s candles with TZ offset
    formatted_1s = []
    for c in unique_1s:
        try:
            ts = int(float(c.get("time", c.get("timestamp", 0))))
            tz = _get_tz_offset()
            aligned = ((ts + tz) // 1) * 1  # align to 1s boundary with TZ
            o = float(c.get("open", 0) or 0)
            h = float(c.get("high", c.get("max", 0)) or 0)
            l = float(c.get("low", c.get("min", 0)) or 0)
            cl = float(c.get("close", 0) or 0)
            v = int(c.get("volume", c.get("vol", 0)) or 0)
            if o > 0 and h > 0 and l > 0 and cl > 0:
                formatted_1s.append({
                    'time': aligned, 'open': o, 'high': h, 'low': l,
                    'close': cl, 'volume': v
                })
        except Exception:
            continue
    formatted_1s.sort(key=lambda x: x['time'])
    # v8.4: aggregate into the resolved _sec (not SUBSECOND_SECONDS global) and
    # limit to the resolved _target (not SUBSECOND_HISTORY_CANDLES global).
    aggregated = _aggregate_sub_minute(formatted_1s, _sec)
    result = aggregated[-_target:]
    logmsg(f"[subfetch:{display_name}] DONE: {len(unique_1s)} 1s -> {len(result)} {_label} candles")
    # v8.1: explicit verification -- warn if below the requested 500 target
    if len(result) < SUBSECOND_HISTORY_CANDLES:
        logmsg(
            f"[subfetch:{display_name}] WARNING: only {len(result)} {SUBSECOND_LABEL} candles "
            f"(target={SUBSECOND_HISTORY_CANDLES}). Server history may be limited for this asset."
        )
    return result


async def fetch_1s_and_aggregate_to_1m(asset: Asset, idx: int = 1, total: int = 1) -> list:
    """v8.6: Fetch 1-second candles and aggregate them to 1-minute candles.

    This is used as the most granular bridge for M1 mode -- the resulting 1m candles
    fill the gap between the historical 1m fetch's last candle and the live stream's
    current candle. Because each 1m candle is built from 60 consecutive 1s candles,
    there are NO gaps in the aggregated 1m candle (assuming the server's 1s data is
    continuous, which it is for popular OTC pairs).

    Args:
        asset: the Asset to fetch 1s candles for
        idx, total: progress info for logging

    Returns:
        (candles_1m, n_1s) -- the aggregated 1m candles and the raw 1s source count
    """
    # v8.5: return (candles_1m, n_1s) tuple so the caller can print the 1s
    # source count in the console before the historical fetch begins.
    if not M1_USE_1S_BRIDGE:
        return [], 0
    _fetch_start = time.time()
    try:
        candles_1s = await asyncio.wait_for(
            fetch_subsecond_history(
                asset,
                idx=idx,
                total=total,
                subsecond_seconds=1,
                target_candles=M1_1S_BRIDGE_TARGET,
                label="1S",
            ),
            timeout=M1_BRIDGE_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logmsg(f"[1s_bridge:{asset.symbol}] 1s fetch timeout after {M1_BRIDGE_TIMEOUT}s")
        return [], 0
    except Exception as e:
        logmsg(f"[1s_bridge:{asset.symbol}] 1s fetch failed: {e}")
        return [], 0
    if not candles_1s:
        logmsg(f"[1s_bridge:{asset.symbol}] 1s returned 0 candles")
        return [], 0
    # Aggregate 1s -> 1m (every 60 consecutive 1s candles = 1 1m candle).
    # This is the most granular aggregation -- if the 1s data is continuous,
    # the resulting 1m candle has NO gaps (the user's explicit request).
    candles_1m = _aggregate_sub_minute(candles_1s, 60)
    _fetch_elapsed = time.time() - _fetch_start
    # v8.5/v8.6: print a clear console line showing the 1s fetch happened --
    # the user explicitly asked "must print the loading of those candles before
    # loading 1-minute candles". Use 'print' (not logmsg) so it shows on the
    # console, not just the verbose log. This print fires BEFORE the historical
    # 1m fetch begins.
    _display = pretty_asset_name(asset.symbol)
    print(
        f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{_display:<25}{Colors.RESET} "
        f"{Colors.DIM}fetched {len(candles_1s)} 1s candles in {_fetch_elapsed:.1f}s "
        f"-> {len(candles_1m)} 1m bridge{Colors.RESET}"
    )
    logmsg(
        f"[1s_bridge:{asset.symbol}] {len(candles_1s)} 1s -> {len(candles_1m)} 1m bridge candles"
    )
    return candles_1m, len(candles_1s)


async def subsecond_stream(asset: Asset):
    """Dedicated stream for subsecond timeframes (5s/10s/15s/30s).

    - Subscribes to realtime ticks (same WS subscription as normal)
    - Polls realtime_candles[asset] for tick data
    - Aggregates ticks into subsecond candle windows
    - Writes HST directly (bypasses MT4_WRITER.sync_state entirely)
    - Keeps last SUBSECOND_MAX_CANDLES (200) candles
    - NO gap filler, NO history fetch
    """
    internal = asset.api_symbol
    try:
        try:
            await wait_until(
                lambda: not (CONNECTION_ALIVE and CLIENT is None),
                timeout=10.0,
                poll_interval=0.2,
            )
        except asyncio.TimeoutError:
            pass
        if not CONNECTION_ALIVE or CLIENT is None:
            asset.streaming = False
            return
        # Subscribe to realtime 1-second ticks (period=1, always supported)
        # We aggregate locally into subsecond windows
        await CLIENT.start_candles_stream(internal, 1)
        await asyncio.sleep(0.5)
        asset.streaming = True
        asset.candles = []
        # Write empty HST immediately so MT4 can open the chart
        _subsecond_write_hst(asset.symbol, [{'time': _subsecond_align(int(time.time())), 'open': 0, 'high': 0, 'low': 0, 'close': 0, 'volume': 0}])
        last_write = time.time()
        # Fetch historical subsecond candles in the BACKGROUND using create_task
        # (run_coroutine_threadsafe doesn't work from inside the same loop)
        display_name = pretty_asset_name(internal)
        async def _background_history_fetch():
            try:
                historical = await asyncio.wait_for(fetch_subsecond_history(asset), timeout=60)
                if historical and len(historical) > 0:
                    # Merge: keep historical candles older than any tick-collected candles
                    if asset.candles:
                        oldest_tick_time = asset.candles[0]['time']
                        historical_to_keep = [c for c in historical if c['time'] < oldest_tick_time]
                        asset.candles = historical_to_keep + asset.candles
                    else:
                        asset.candles = historical
                    asset.candles = asset.candles[-SUBSECOND_MAX_CANDLES:]
                    if asset.candles and asset.price == 0:
                        asset.price = asset.candles[-1]['close']
                    # Write HST with merged data
                    _subsecond_write_hst(asset.symbol, asset.candles)
                    logmsg(f"[substream:{internal}] {len(historical)} history candles loaded + ticks active")
                else:
                    logmsg(f"[substream:{internal}] no history (ticks only)")
            except asyncio.TimeoutError:
                logmsg(f"[substream:{internal}] history fetch timeout (ticks only)")
            except Exception as e:
                logmsg(f"[substream:{internal}] background history fetch failed: {e}")
        # Schedule on the same loop — keep a strong reference to avoid GC
        _task = asyncio.create_task(_background_history_fetch())
        # Store on asset to prevent garbage collection
        if not hasattr(asset, '_bg_tasks'):
            asset._bg_tasks = set()
        asset._bg_tasks.add(_task)
        _task.add_done_callback(asset._bg_tasks.discard)
    except Exception as e:
        logmsg(f"[substream:{internal}] failed to start: {e}")
        asset.streaming = False
        return
    consecutive_errors = 0
    while CONNECTION_ALIVE:
        try:
            if CLIENT is None or not getattr(getattr(CLIENT, 'api', None), 'state', None) or getattr(CLIENT.api.state, 'status', None) != 1:
                await asyncio.sleep(0.2)
                continue
            candle = None
            if hasattr(CLIENT, 'api') and CLIENT.api:
                candle = CLIENT.api.realtime_candles.get(internal)
            if candle:
                consecutive_errors = 0
                if isinstance(candle, list) and len(candle) >= 3:
                    ts, price = int(candle[1]), float(candle[2])
                elif isinstance(candle, dict):
                    ts = int(candle.get("time", candle.get("timestamp", time.time())))
                    price = float(candle.get("price", candle.get("close", 0)))
                else:
                    await asyncio.sleep(STREAM_POLL_INTERVAL)
                    continue
                if price > 0 and ts > 0:
                    # Align to subsecond window
                    window_start = _subsecond_align(ts)
                    if asset.candles:
                        last_candle = asset.candles[-1]
                        if window_start < last_candle['time']:
                            # stale tick — ignore
                            pass
                        elif window_start == last_candle['time']:
                            # update current candle
                            last_candle['high'] = max(last_candle['high'], price)
                            last_candle['low'] = min(last_candle['low'], price)
                            last_candle['close'] = price
                            last_candle['volume'] += 1
                        else:
                            # new window — append
                            asset.candles.append({
                                'time': window_start, 'open': price, 'high': price,
                                'low': price, 'close': price, 'volume': 1
                            })
                    else:
                        asset.candles.append({
                            'time': window_start, 'open': price, 'high': price,
                            'low': price, 'close': price, 'volume': 1
                        })
                    # keep last SUBSECOND_MAX_CANDLES
                    if len(asset.candles) > SUBSECOND_MAX_CANDLES:
                        asset.candles = asset.candles[-SUBSECOND_MAX_CANDLES:]
                    # update price display
                    if asset.price != price:
                        asset.previous_price = asset.price
                    asset.price = price
                    asset.updates += 1
                    asset.last_update_time = time.time()
                    # write HST every 0.5s
                    now = time.time()
                    if now - last_write > 0.5:
                        _subsecond_write_hst(asset.symbol, asset.candles)
                        last_write = now
            await asyncio.sleep(STREAM_POLL_INTERVAL)
        except asyncio.CancelledError:
            asset.streaming = False
            raise
        except asyncio.TimeoutError:
            continue
        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors >= 10:
                logmsg(f"[substream:{internal}] too many consecutive errors, stopping")
                asset.streaming = False
                return
            await asyncio.sleep(0.2)
    asset.streaming = False


async def realtime_stream(asset: Asset):
    internal = asset.api_symbol
    try:
        # ===== EVENT-DRIVEN FIX =====
        # :
        # while CONNECTION_ALIVE and CLIENT is None: await asyncio.sleep(0.5)
        # timeout 200ms .
        try:
            await wait_until(
                lambda: not (CONNECTION_ALIVE and CLIENT is None),
                timeout=10.0,
                poll_interval=0.2,
            )
        except asyncio.TimeoutError:
            pass
        if not CONNECTION_ALIVE or CLIENT is None:
            asset.streaming = False
            return
        # For sub-minute timeframes, subscribe to period=1 (1s candles, always supported)
        # _align_time then buckets ticks into PERIOD_SECONDS (5s, 10s, 15s, 30s)
        #
        # v8.10: when M1_USE_1S_BRIDGE is True (which includes both TEST MODE
        # and the full flow), FORCE stream_period=1 even though PERIOD_SECONDS
        # == 60. This subscribes to 1s ticks (NOT 1m snapshots), so the server
        # doesn't send the 199-candle initial 1m burst. The 1s ticks are
        # bucketed into 1m candles by update_candle via _align_time, updating
        # the last candle for live price every second.
        if PERIOD_SECONDS == 60 and M1_USE_1S_BRIDGE:
            stream_period = 1  # 1s ticks, aggregate to 1m locally
        else:
            stream_period = 1 if PERIOD_SECONDS < 60 else PERIOD_SECONDS
        await CLIENT.start_candles_stream(internal, stream_period)
        await asyncio.sleep(0.3)  # reduced from 1.5s to minimize gap with historical fetch
        asset.streaming = True
        # ===== FIX 12: MT4_WRITER.sync_state 1000 =====
        # : MT4_WRITER.update_candle sync_state
        # => ~19 (1KB) 1000 (44KB)
        # : asset.candles (1000 ) sync_state[derived_symbol]
        # realtime_stream update_candle
        # sync_state 1000 .
        if asset.candles and asset.symbol not in MT4_WRITER.sync_state:
            MT4_WRITER.sync_state[asset.symbol] = {
                'period': PERIOD,
                'candles': list(asset.candles),  # 1000
                'last_write': 0,
                'last_price': float(asset.candles[-1]['close']) if asset.candles else 0.0,
            }
    except Exception as e:
        logmsg(f"[stream:{internal}] failed to start stream: {e}")
        asset.streaming = False
        return
    consecutive_errors = 0
    while CONNECTION_ALIVE:
        try:
            if CLIENT is None or not getattr(getattr(CLIENT, 'api', None), 'state', None) or getattr(CLIENT.api.state, 'status', None) != 1:
                # ===== EVENT-DRIVEN FIX =====
                # await asyncio.sleep(1) — polling (200ms)
                await asyncio.sleep(0.2)
                continue
            candle = None
            if not candle and hasattr(CLIENT, 'api') and CLIENT.api:
                candle = CLIENT.api.realtime_candles.get(internal)
            if candle:
                consecutive_errors = 0
                if isinstance(candle, list) and len(candle) >= 3:
                    ts, price = int(candle[1]), float(candle[2])
                elif isinstance(candle, dict):
                    ts = int(candle.get("time", candle.get("timestamp", time.time())))
                    price = float(candle.get("price", candle.get("close", 0)))
                else:
                    await asyncio.sleep(STREAM_POLL_INTERVAL)
                    continue
                if price > 0 and ts > 0:
                    # ===== FIX 10: MT4_WRITER.update_candle asset.mark_dirty =====
                    # HST MT4Writer.write_to_file ( )
                    # MT4_WRITER.update_candle sync_state[derived_symbol] + HST 200ms
                    try:
                        MT4_WRITER.update_candle(asset.symbol, PERIOD, {'time': ts, 'price': price})
                    except Exception:
                        pass
                    # asset.candles ( )
                    # FIX L5: _align_time ( tz_offset) asset.candles
                    # sync_state HST. (ts // 60 * 60)
                    # tz_offset => 1+ HST.
                    aligned_time = _align_time(ts)
                    # FIX STALE-CANDLE v2: same logic as update_candle
                    _is_new_candle = False
                    if asset.candles:
                        last_candle = asset.candles[-1]
                        if aligned_time < last_candle['time']:
                            pass  # tick for closed minute - ignore
                        elif last_candle['time'] == aligned_time:
                            last_candle['high'] = max(last_candle['high'], price)
                            last_candle['low'] = min(last_candle['low'], price)
                            last_candle['close'] = price
                        else:
                            # new candle - fill gap with flat candles first
                            _is_new_candle = True
                            period_secs = PERIOD_SECONDS if PERIOD_SECONDS > 0 else 60
                            gap = (aligned_time - last_candle['time']) // period_secs
                            if gap > 1:
                                last_close = last_candle['close']
                                fill_time = last_candle['time'] + period_secs
                                while fill_time < aligned_time:
                                    asset.candles.append({
                                        'time': fill_time,
                                        'open': last_close, 'high': last_close,
                                        'low': last_close, 'close': last_close, 'volume': 0,
                                    })
                                    fill_time += period_secs
                            asset.candles.append({'time': aligned_time, 'open': price, 'high': price, 'low': price, 'close': price, 'volume': 1})
                    else:
                        _is_new_candle = True
                        asset.candles.append({'time': aligned_time, 'open': price, 'high': price, 'low': price, 'close': price, 'volume': 1})
                    if len(asset.candles) > INITIAL_CANDLES: asset.candles = asset.candles[-INITIAL_CANDLES:]
                    # FIX G: ( )
                    if asset.price != price:
                        asset.previous_price = asset.price
                    asset.price = price
                    asset.updates += 1
                    asset.last_update_time = time.time()
                    # v9.0: Update web dashboard on every live tick.
                    # - Default path (full_resync=False): O(1) tick cache update.
                    #   This is what the chart polls at 50ms — extremely fast.
                    # - On new candle close (full_resync=True): refreshes the full
                    #   candle list so the chart sees the new bar.
                    try:
                        _web_update_asset(asset, full_resync=_is_new_candle)
                    except Exception:
                        pass
                    # asset.mark_dirty() — MT4_WRITER.update_candle
            await asyncio.sleep(STREAM_POLL_INTERVAL)
        except asyncio.CancelledError:
            asset.streaming = False
            raise
        except asyncio.TimeoutError: continue
        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors >= 10:
                logmsg(f"[stream:{internal}] too many consecutive errors, stopping stream")
                asset.streaming = False
                return
            # ===== EVENT-DRIVEN FIX =====
            # await asyncio.sleep(1) — polling (200ms)
            await asyncio.sleep(0.2)
    asset.streaming = False


# ===== FIX B: (> ) =====
# : " ".
# auto_reconnect
# LONG_DISCONNECT_THRESHOLD. 1000
# HST streams —
# .
async def refetch_all_candles():
    """ .

 :
 1. streams caches 
 2. sync_state MT4_WRITER ( HST)
 3. fetch_candles_with_retry ( 1000 )
 4. realtime_stream 
 5. mt4_gap_filler 
 """
    if not ALL_STREAMING_ASSETS:
        logmsg("[refetch_all] no assets to re-fetch")
        return
    print(f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  FULL RE-FETCH: long disconnect detected — refreshing all candles{Colors.RESET}")
    print(f"  • Assets: {len(ALL_STREAMING_ASSETS)}")
    print(f"  • Target per asset: {INITIAL_CANDLES} candles")
    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")
    # 1) streams
    for asset in ALL_STREAMING_ASSETS:
        try:
            if asset.stream_task and not asset.stream_task.done():
                asset.stream_task.cancel()
        except Exception:
            pass
        asset.streaming = False
        asset.stream_task = None
        asset.candles = []
        asset.last_saved_close = 0.0
        asset.last_saved_candle_time = 0
        asset.last_saved_candle_count = 0
        asset.dirty = True
        asset._gap_filled = False
        asset.updates = 0
        asset.last_update_time = 0
        # sync_state MT4_WRITER
        if asset.symbol in MT4_WRITER.sync_state:
            try: del MT4_WRITER.sync_state[asset.symbol]
            except Exception: pass
        if asset.symbol in MT4_WRITER._gap_filled:
            MT4_WRITER._gap_filled[asset.symbol] = False
        # Clear the SQLite-side gap_state flag too so fill_gap_once will run
        # again for this asset after the full re-fetch.
        try:
            MT4_WRITER.candle_store.clear_symbol(asset.symbol)
        except Exception:
            pass
    # 2)
    total_loaded = 0
    total_assets = len(ALL_STREAMING_ASSETS)
    consecutive_disconnects = 0
    for idx, asset in enumerate(ALL_STREAMING_ASSETS, 1):

        if not CONNECTION_ALIVE or CLIENT is None or CLIENT.api is None:
            logmsg(f"[refetch_all] connection lost again at asset {idx}/{total_assets}; aborting re-fetch")
            break
        display = pretty_asset_name(asset.api_symbol)
        start_time = time.time()
        if IS_SUBSECOND:
            # Subsecond mode: no history to re-fetch, just restart stream
            print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.CYAN}subsecond — no history to refetch{Colors.RESET}")
        else:
            try:
                candles_count, attempts = await fetch_candles_with_retry(
                    asset, max_retries=MAX_FETCH_RETRIES, idx=idx, total=total_assets
                )
                elapsed = time.time() - start_time
                if candles_count >= MIN_CANDLES_THRESHOLD:
                    total_loaded += candles_count
                    consecutive_disconnects = 0
                    attempts_str = "" if attempts == 1 else f" ({attempts} attempts)"
                    print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.GREEN}{candles_count} candles in {elapsed:.1f}s{attempts_str}{Colors.RESET}")
                else:
                    print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.RED}Only {candles_count} candles{Colors.RESET}")
            except Exception as e:
                print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.RED}Error: {str(e)[:30]}{Colors.RESET}")
                if "Connection" in str(e) or "closed" in str(e).lower():
                    consecutive_disconnects += 1
                    if consecutive_disconnects >= MAX_RECONNECTS_DURING_FETCH:
                        logmsg(f"[refetch_all] too many disconnects ({consecutive_disconnects}); aborting")
                        break
        # 3) restart stream
        try:
            asset.stream_task = asyncio.run_coroutine_threadsafe(subsecond_stream(asset) if IS_SUBSECOND else realtime_stream(asset), ASYNC_LOOP)
        except Exception as e:
            logmsg(f"[refetch_all] failed to restart stream for {asset.symbol}: {e}")
        await asyncio.sleep(FETCH_ASSET_DELAY)
    # 4)
    if CONNECTION_ALIVE and CLIENT is not None and CLIENT.api is not None:
        try:
            asyncio.run_coroutine_threadsafe(mt4_gap_filler(), ASYNC_LOOP)
        except Exception as e:
            logmsg(f"[refetch_all] failed to schedule gap filler: {e}")
    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")
    print(f"{Colors.GREEN}  Full re-fetch complete: {total_loaded} candles across {total_assets} assets{Colors.RESET}")
    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}\n")

# ==============================================================================
# SECTION 9: MT4 SYNC ENGINE ( — )
# ==============================================================================

# ------------------------------------------------------------------------------
# CandleStore: SQLite-backed persistent candle storage.
# ------------------------------------------------------------------------------
# Why SQLite instead of JSON files:
#   - JSON is slow: full file rewrite on every save, full file load on every
#     read, no indexing. For ~1000 candles per asset across many assets this
#     wastes I/O and risks corruption if the process is killed mid-write.
#   - SQLite is transactional, atomic, indexed by (symbol, time), and
#     supports efficient range queries ("give me all candles for symbol X
#     from time A to time B") without loading the whole table into memory.
#   - Concurrent reads + a single writer are safe out of the box.
#
# Schema:
#   candles(symbol TEXT, time INTEGER, open REAL, high REAL, low REAL,
#           close REAL, volume INTEGER, PRIMARY KEY(symbol, time))
#   gap_state(symbol TEXT PRIMARY KEY, filled INTEGER, last_fill_at REAL)
#       - 'filled' is 0/1 and tracks whether fill_gap_once has already
#         succeeded for this asset. Once it is 1, MT4Writer.fill_gap_once
#         stops touching closed candles for this asset entirely.
# ------------------------------------------------------------------------------
import sqlite3 as _sqlite3
import threading as _threading

class CandleStore:
    """Thread-safe SQLite-backed candle persistence layer.

    All public methods are safe to call from any thread. A single write
    connection (guarded by a lock) serializes writes; reads use a short-lived
    read-only connection per call.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._write_lock = _threading.Lock()
        self._write_conn: Optional[_sqlite3.Connection] = None
        # Make sure parent dir exists
        try:
            parent = os.path.dirname(db_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
        except Exception as e:
            pass  # silenced - non-essential diagnostic
        # Init schema on a short-lived connection
        self._init_schema()

    def _init_schema(self):
        try:
            conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                conn.execute("PRAGMA journal_mode=WAL;")    # crash-safe, fast writes
                conn.execute("PRAGMA synchronous=NORMAL;")  # safe + fast
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS candles (
                        symbol TEXT NOT NULL,
                        time   INTEGER NOT NULL,
                        open   REAL NOT NULL,
                        high   REAL NOT NULL,
                        low    REAL NOT NULL,
                        close  REAL NOT NULL,
                        volume INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (symbol, time)
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_candles_symbol_time
                    ON candles(symbol, time)
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS gap_state (
                        symbol        TEXT PRIMARY KEY,
                        filled        INTEGER NOT NULL DEFAULT 0,
                        last_fill_at  REAL NOT NULL DEFAULT 0
                    )
                """)
            finally:
                conn.close()
        except Exception as e:
            pass  # silenced - non-essential diagnostic

    # ------------------------------------------------------------------ writes
    def _get_write_conn(self) -> _sqlite3.Connection:
        if self._write_conn is None:
            self._write_conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            self._write_conn.execute("PRAGMA journal_mode=WAL;")
            self._write_conn.execute("PRAGMA synchronous=NORMAL;")
        return self._write_conn

    def upsert_candles(self, symbol: str, candles: list) -> int:
        """Insert-or-replace a batch of candles for the given symbol.
        Returns the number of rows written."""
        if not candles:
            return 0
        with self._write_lock:
            conn = self._get_write_conn()
            rows = 0
            try:
                conn.execute("BEGIN IMMEDIATE;")
                for c in candles:
                    conn.execute(
                        "INSERT OR REPLACE INTO candles(symbol, time, open, high, low, close, volume) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?);",
                        (symbol, int(c['time']), float(c['open']), float(c['high']),
                         float(c['low']), float(c['close']), int(c.get('volume', 0)))
                    )
                    rows += 1
                conn.execute("COMMIT;")
            except Exception:
                try: conn.execute("ROLLBACK;")
                except Exception: pass
                pass  # silenced - non-essential diagnostic
                return 0
            return rows

    def append_new_candles(self, symbol: str, candles: list, after_time: int = 0) -> int:
        """Append candles whose time > after_time. Existing candles with time
        <= after_time are left untouched (frozen). Returns number of rows
        actually inserted (not the number replaced)."""
        if not candles:
            return 0
        with self._write_lock:
            conn = self._get_write_conn()
            inserted = 0
            try:
                conn.execute("BEGIN IMMEDIATE;")
                for c in candles:
                    t = int(c['time'])
                    if t <= after_time:
                        continue    # frozen - skip
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO candles(symbol, time, open, high, low, close, volume) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?);",
                        (symbol, t, float(c['open']), float(c['high']),
                         float(c['low']), float(c['close']), int(c.get('volume', 0)))
                    )
                    if cur.rowcount > 0:
                        inserted += 1
                conn.execute("COMMIT;")
            except Exception:
                try: conn.execute("ROLLBACK;")
                except Exception: pass
                pass  # silenced - non-essential diagnostic
                return 0
            return inserted

    def set_gap_filled(self, symbol: str, filled: bool = True, at_ts: float = None):
        if at_ts is None:
            at_ts = time.time()
        with self._write_lock:
            conn = self._get_write_conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    "INSERT INTO gap_state(symbol, filled, last_fill_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(symbol) DO UPDATE SET filled=excluded.filled, last_fill_at=excluded.last_fill_at;",
                    (symbol, 1 if filled else 0, float(at_ts))
                )
                conn.execute("COMMIT;")
            except Exception:
                try: conn.execute("ROLLBACK;")
                except Exception: pass

    def is_gap_filled(self, symbol: str) -> Tuple[bool, float]:
        """Returns (filled, last_fill_at)."""
        try:
            conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                cur = conn.execute(
                    "SELECT filled, last_fill_at FROM gap_state WHERE symbol=?;",
                    (symbol,)
                )
                row = cur.fetchone()
                if row is None:
                    return (False, 0.0)
                return (bool(row[0]), float(row[1]))
            finally:
                conn.close()
        except Exception as e:
            pass  # silenced - non-essential diagnostic
            return (False, 0.0)

    # ------------------------------------------------------------------- reads
    def get_candles(self, symbol: str, limit: Optional[int] = None) -> list:
        """Return all candles for the symbol, sorted by time ascending.
        If limit is given, return only the last `limit` candles."""
        try:
            conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                if limit is None:
                    cur = conn.execute(
                        "SELECT time, open, high, low, close, volume FROM candles "
                        "WHERE symbol=? ORDER BY time ASC;",
                        (symbol,)
                    )
                else:
                    # Use a subselect to get the last N rows by time, then sort ascending.
                    cur = conn.execute(
                        "SELECT time, open, high, low, close, volume FROM candles "
                        "WHERE symbol=? ORDER BY time DESC LIMIT ?;",
                        (symbol, int(limit))
                    )
                    rows = cur.fetchall()
                    rows.reverse()
                    return [{
                        'time': r[0], 'open': r[1], 'high': r[2],
                        'low': r[3], 'close': r[4], 'volume': r[5]
                    } for r in rows]
                rows = cur.fetchall()
                return [{
                    'time': r[0], 'open': r[1], 'high': r[2],
                    'low': r[3], 'close': r[4], 'volume': r[5]
                } for r in rows]
            finally:
                conn.close()
        except Exception as e:
            pass  # silenced - non-essential diagnostic
            return []

    def get_max_time(self, symbol: str) -> int:
        """Return the largest candle timestamp stored for the symbol, or 0."""
        try:
            conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                cur = conn.execute(
                    "SELECT MAX(time) FROM candles WHERE symbol=?;",
                    (symbol,)
                )
                row = cur.fetchone()
                return int(row[0]) if row and row[0] is not None else 0
            finally:
                conn.close()
        except Exception as e:
            pass  # silenced - non-essential diagnostic
            return 0

    def count(self, symbol: str) -> int:
        try:
            conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                cur = conn.execute(
                    "SELECT COUNT(*) FROM candles WHERE symbol=?;",
                    (symbol,)
                )
                row = cur.fetchone()
                return int(row[0]) if row else 0
            finally:
                conn.close()
        except Exception as e:
            pass  # silenced - non-essential diagnostic
            return 0

    def clear_symbol(self, symbol: str) -> int:
        """Delete all candles + gap_state for a symbol (used by full re-fetch)."""
        with self._write_lock:
            conn = self._get_write_conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                cur = conn.execute("DELETE FROM candles WHERE symbol=?;", (symbol,))
                deleted = cur.rowcount
                conn.execute("DELETE FROM gap_state WHERE symbol=?;", (symbol,))
                conn.execute("COMMIT;")
                return deleted
            except Exception:
                try: conn.execute("ROLLBACK;")
                except Exception: pass
                return 0


# Module-level singleton (created lazily so the path can be picked once
# after APPDATA is available at runtime).
_CANDLE_STORE: Optional[CandleStore] = None
_CANDLE_STORE_LOCK = _threading.Lock()

def get_candle_store() -> CandleStore:
    """Lazy-init the global CandleStore.

    The DB lives NEXT TO THE SCRIPT / EXE (not in APPDATA) so it is easy to
    bundle with a PyInstaller exe and easy for the user to find / back up.
    - When run as a script: candles.db is created in the script's directory.
    - When frozen with PyInstaller (one-file): candles.db is created in the
      directory the exe runs from (sys.executable's parent).
    """
    global _CANDLE_STORE
    if _CANDLE_STORE is not None:
        return _CANDLE_STORE
    with _CANDLE_STORE_LOCK:
        if _CANDLE_STORE is None:
            # Resolve the directory the script / exe lives in.
            # When frozen with PyInstaller, sys.executable points to the exe
            # and we want the DB next to it (not inside the temp _MEIPASS dir).
            if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                base_dir = os.path.dirname(os.path.abspath(sys.executable))
            else:
                base_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(base_dir, 'candles.db')
            _CANDLE_STORE = CandleStore(db_path)
        return _CANDLE_STORE


# ==============================================================================
# SECTION 9.1: MT4 WRITER (uses CandleStore instead of JSON snapshots)
# ==============================================================================
class MT4Writer:
    """ MT4 .
 
 :
 - sync_state[asset] {period, candles, last_write, last_price}
 - seed_history: + HST 
 - update_candle: + HST 200ms
 - fill_gap_once: 20 + HST
 
 :
 - derived_symbol (AUDJPY-OTC) api_symbol 
 - PERIOD=1 (M1) 60 (H1) => AUDJPY-OTC1.hst
 - makedirs + retry + silent errors ( FIX 4/8)
 """
    def __init__(self):
        appdata = os.environ.get('APPDATA', '') or os.environ.get('HOME', '')
        self.mt4_history_path = os.path.join(appdata, 'MetaQuotes', 'Terminal', 'Common', 'Files', 'qx_hst')
        try:
            os.makedirs(self.mt4_history_path, exist_ok=True)
        except Exception as e:
            logmsg(f"Cannot create MT4 folder: {e}")
        # ===== FIX 10: sync_state derived_symbol ( AUDJPY-OTC) =====
        # seed_history + update_candle + fill_gap_once
        # => (AUDJPY-OTC1.hst)
        self.sync_state: Dict[str, Any] = {}
        self._writing_queue = set()
        self._gap_filled = {}
        # ===== FIX L8: =====
        # GAP_FILL_REFRESH_INTERVAL ( )
        # => .
        self._gap_filled_at: Dict[str, float] = {}
        # ---- PERSISTENT STORAGE: SQLite-backed candle store ----------------
        # CandleStore replaces the previous JSON snapshot approach. SQLite is
        # transactional, atomic, indexed by (symbol, time), and far faster than
        # writing/loading a 30 KB JSON file on every cycle. The DB lives at:
        #   %APPDATA%\MetaQuotes\Terminal\Common\Files\qx_hst_snapshots\candles.db
        # See SECTION 9 above for the CandleStore class definition.
        self._candle_store: Optional[CandleStore] = None   # lazy via get_candle_store()

    @property
    def candle_store(self) -> "CandleStore":
        """Lazy accessor so the DB connection is created after APPDATA is set."""
        if self._candle_store is None:
            self._candle_store = get_candle_store()
        return self._candle_store

    def load_snapshot(self, derived_symbol: str) -> Optional[list]:
        """Load candles for an asset from the SQLite store.
        Returns None if no candles exist (so seed_history falls back to the API).
        Also refreshes the in-memory gap_state from the DB."""
        try:
            stored = self.candle_store.get_candles(derived_symbol, limit=INITIAL_CANDLES)
            if not stored:
                return None
            # refresh in-memory gap_state from DB
            filled, last_at = self.candle_store.is_gap_filled(derived_symbol)
            self._gap_filled[derived_symbol] = filled
            self._gap_filled_at[derived_symbol] = last_at
            return stored
        except Exception as e:
            pass  # silenced - non-essential diagnostic
            return None

    def save_snapshot(self, derived_symbol: str, candles: list) -> None:
        """Persist the current candle list to the SQLite store.
        Called after seed_history + after each successful fill_gap_once."""
        try:
            self.candle_store.upsert_candles(derived_symbol, candles)
        except Exception as e:
            pass  # silenced - non-essential diagnostic

    def get_digits(self, symbol: str, price: float = 0.0) -> int:
        # FIX J: _resolve_digits ( mt4_digits.json)
        return _resolve_digits(symbol, price)

    def generate_hst_buffer(self, symbol: str, period: int, candles: list) -> bytes:
        # For sub-minute timeframes, write period=1 (M1) in the HST header
        # so MT4 opens it as a normal M1 file. The candles inside have actual
        # 5s/10s/15s/30s timestamps. For 60s+ timeframes, store the MT4 period int.
        header_period = 1 if PERIOD_SECONDS < 60 else period
        header = bytearray(148)
        struct.pack_into('<I', header, 0, 400)
        struct.pack_into('64s', header, 4, b'MetaQuotes Software Corp.'.ljust(64, b'\x00'))
        struct.pack_into('12s', header, 68, symbol[:12].encode('ascii').ljust(12, b'\x00'))
        struct.pack_into('<I', header, 80, header_period)
        first_price = candles[0]['close'] if candles else 0.0
        digits = self.get_digits(symbol, first_price)
        struct.pack_into('<I', header, 84, digits)
        struct.pack_into('<I', header, 88, 0)
        struct.pack_into('<I', header, 92, 0)
        body_size = len(candles) * 44
        buffer = bytearray(148 + body_size)
        buffer[:148] = header
        offset = 148
        for c in candles:
            struct.pack_into('<I', buffer, offset, int(c['time']))
            struct.pack_into('<d', buffer, offset + 4, float(c['open']))
            struct.pack_into('<d', buffer, offset + 12, float(c['low']))
            struct.pack_into('<d', buffer, offset + 20, float(c['high']))
            struct.pack_into('<d', buffer, offset + 28, float(c['close']))
            struct.pack_into('<Q', buffer, offset + 36, int(c.get('volume', 0)))
            offset += 44
        return bytes(buffer)

    def update_candle(self, asset: str, period: int, tick: dict):
        """ + HST 200ms ( ).

 Args:
 asset: derived_symbol ( "AUDJPY-OTC") — 
 period: MT4 timeframe (PERIOD=1 for M1) — 
 tick: {'time': int, 'price': float}
 """
        if asset not in self.sync_state:
            self.sync_state[asset] = {'period': period, 'candles': [], 'last_write': 0, 'last_price': 0.0}
        state = self.sync_state[asset]
        # ===== FIX L6: _align_time ( tz_offset + ) =====
        # —
        # seed_history fill_gap_once fetch_candles_once.
        aligned_time = _align_time(tick['time'])

        # FIX STALE-CANDLE v2: only the last candle (current/open) can be updated.
        # All candles before it are closed and must never be touched.
        if state['candles']:
            last_time = state['candles'][-1]['time']
            if aligned_time < last_time:
                # tick for a closed minute - ignore (protect closed candles)
                return
            elif aligned_time == last_time:
                last = state['candles'][-1]
                if tick['price'] == state['last_price']: return
                last['high'] = max(last['high'], tick['price'])
                last['low'] = min(last['low'], tick['price'])
                last['close'] = tick['price']
                last['volume'] += 1
            else:
                # new candle - check if there's a gap and fill it with flat candles
                period_secs = PERIOD_SECONDS if PERIOD_SECONDS > 0 else 60
                gap = (aligned_time - last_time) // period_secs
                if gap > 1:
                    # Fill gap with flat candles (use last close as price)
                    last_close = state['candles'][-1]['close']
                    fill_time = last_time + period_secs
                    while fill_time < aligned_time:
                        state['candles'].append({
                            'time': fill_time,
                            'open': last_close,
                            'high': last_close,
                            'low': last_close,
                            'close': last_close,
                            'volume': 0,
                        })
                        fill_time += period_secs
                # Now append the new candle (becomes the last)
                state['candles'].append({
                    'time': aligned_time, 'open': tick['price'], 'high': tick['price'],
                    'low': tick['price'], 'close': tick['price'], 'volume': 1,
                })
        else:
            state['candles'].append({
                'time': aligned_time, 'open': tick['price'], 'high': tick['price'],
                'low': tick['price'], 'close': tick['price'], 'volume': 1,
            })
        if len(state['candles']) > 1000:
            state['candles'] = state['candles'][-1000:]
        state['last_price'] = tick['price']
        now = time.time()
        if now - state['last_write'] > 0.2:
            self.write_to_file(asset, period, state['candles'])
            state['last_write'] = now

    def write_to_file(self, asset: str, period: int, candles: list):
        """ HST {asset}{period}.hst ( AUDJPY-OTC1.hst).

 Args:
 asset: derived_symbol ( "AUDJPY-OTC")
 period: MT4 timeframe (PERIOD=1 for M1)
"""
        # DISABLED: server no longer writes HST files (user request).
        # The web dashboard (Flask) is now the ONLY output — no disk writes.
        if not WRITE_HST_FILES_ENABLED:
            return
        if asset in self._writing_queue: return
        self._writing_queue.add(asset)
        file_name = f"{asset}{period}.hst"
        file_path = os.path.join(self.mt4_history_path, file_name)
        temp_path = file_path + '.tmp'
        # / +
        def _is_silent_error(err_str):
            err_str = err_str.lower()
            return any(x in err_str for x in [
                'winerror 2', 'winerror 5', 'winerror 32', 'winerror 13',
                'introuvable', 'refusé', 'acces refusé', 'access denied',
                'permission', 'used by another', 'ebusy', 'eperm',
                'no such file', 'not found', 'does not exist'
            ])
        # ( WinError 2)
        try:
            os.makedirs(self.mt4_history_path, exist_ok=True)
        except Exception:
            pass
        try:
            buffer = self.generate_hst_buffer(asset, period, candles)
            with open(temp_path, 'wb') as f:
                f.write(buffer)
            # retry WinError 5 + 32
            replaced = False
            for attempt in range(8):
                try:
                    os.replace(temp_path, file_path)
                    replaced = True
                    break
                except (PermissionError, OSError) as e:
                    if _is_silent_error(str(e)):
                        time.sleep(0.05 + 0.05 * attempt)
                        continue
                    raise
            if not replaced:
                # fallback —
                try:
                    with open(file_path, 'wb') as f:
                        f.write(buffer)
                    replaced = True
                except Exception as fallback_err:
                    if not _is_silent_error(str(fallback_err)):
                        logmsg(f"MT4 Write Error for {asset} (fallback): {fallback_err}")
        except OSError as e:
            if not _is_silent_error(str(e)):
                logmsg(f"MT4 Write Error for {asset}: {e}")
        except Exception as e:
            if not _is_silent_error(str(e)):
                logmsg(f"MT4 Write Error for {asset}: {e}")
        finally:
            self._writing_queue.discard(asset)
            if os.path.exists(temp_path):
                try: os.remove(temp_path)
                except Exception: pass

    async def seed_history(self, client, asset_obj, period: int, days: float = 0.75):
        """ + HST ( ).
 
 Args:
 client: Quotex
 asset_obj: Asset ( api_symbol symbol)
 period: MT4 timeframe (PERIOD=1 for M1) — get_candles PERIOD_SECONDS
 days: (default 0.75 = 18 )
 
 Returns:
 True False 
 """
        api_symbol = asset_obj.api_symbol
        derived_symbol = asset_obj.symbol

        # ---- SNAPSHOT FAST PATH ------------------------------------------------
        # If we have a previously-saved snapshot for this asset, use it directly.
        # This avoids re-fetching historical candles from the API on every restart
        # and prevents the "candles flicker / disappear and reappear" symptom
        # caused by the API returning slightly different candle data each call.
        # The streaming update_candle() path will simply append new candles as
        # they happen, and fill_gap_once() will only ADD new closed candles
        # (never replace existing ones, since the snapshot marks them as frozen).
        try:
            snap = self.load_snapshot(derived_symbol)
            if snap and len(snap) >= 2:
                snap = sorted(snap, key=lambda x: x['time'])[-INITIAL_CANDLES:]
                # populate sync_state from the snapshot
                self.sync_state[derived_symbol] = {
                    'period': period,
                    'candles': list(snap),
                    'last_write': 0,
                    'last_price': float(snap[-1]['close']) if snap else 0.0,
                }
                # write HST so MT4 picks them up immediately
                self.write_to_file(derived_symbol, period, snap)
                asset_obj.candles = list(snap)
                if snap:
                    asset_obj.price = snap[-1]['close']
                # gap is considered already filled (frozen) for the snapshot range
                self._gap_filled[derived_symbol] = True
                self._gap_filled_at[derived_symbol] = time.time()
                pass  # silenced - non-essential diagnostic
                return True
        except Exception as _se:
            pass  # silenced - non-essential diagnostic

        try:
            offset_seconds = int(days * 86400)
            # ===== FIX 10: get_candles PERIOD_SECONDS (60s ) =====
            # PERIOD (1 = M1 timeframe)
            candles = await client.get_candles(api_symbol, time.time(), offset_seconds, PERIOD_SECONDS)
            if candles and len(candles) > 0:
                # ===== FIX L7: _align_time ( tz_offset + ) =====
                # `t = int(c.get('time', ...)) + _tz_offset` —
                # => API 22:36:30 22:36:30
                # update_candle 22:36:00 => => .
                # : _align_time tz_offset + => .
                formatted = []
                for c in candles:
                    t = _align_time(int(c.get('time', c.get('timestamp', 0))))
                    o = float(c.get('open', c.get('o', 0)) or 0)
                    h = float(c.get('high', c.get('max', c.get('h', 0))) or 0)
                    l = float(c.get('low', c.get('min', c.get('l', 0))) or 0)
                    cl = float(c.get('close', c.get('c', 0)) or 0)
                    if o > 0 and h > 0 and l > 0 and cl > 0:
                        formatted.append({
                            'time': t, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': 0,
                        })
                formatted.sort(key=lambda x: x['time'])
                seen = set()
                unique_candles = [c for c in formatted if not (c['time'] in seen or seen.add(c['time']))]
                # ===== FIX 10: 1000 + =====
                unique_candles = unique_candles[-INITIAL_CANDLES:]
                # ===== FIX 10: sync_state derived_symbol ( AUDJPY-OTC) =====
                self.sync_state[derived_symbol] = {
                    'period': period, 'candles': unique_candles, 'last_write': 0, 'last_price': 0.0,
                }
                # ===== FIX 10: HST derived_symbol + period (AUDJPY-OTC1.hst) =====
                self.write_to_file(derived_symbol, period, unique_candles)
                # asset_obj.candles ( )
                asset_obj.candles = unique_candles
                if unique_candles:
                    asset_obj.price = unique_candles[-1]['close']
                self._gap_filled[derived_symbol] = False
                # ---- Save the freshly-fetched candles as the snapshot so the next
                # restart uses them as-is and never re-fetches this range. ----
                self.save_snapshot(derived_symbol, unique_candles)
                return True
            return False
        except Exception as e:
            # ( spam)
            err_str = str(e).lower()
            if not any(x in err_str for x in ['winerror', 'permission', 'access', 'closed', 'connection']):
                pass  # — main fetch loop
            return False

    async def fill_gap_once(self, client, asset_obj, period: int):
        """ GAP_FILL_CANDLES + .

 (FIX L9):
 1. _align_time tz_offset + => .
 2. GAP_FILL_REFRESH_INTERVAL => .
 3. _fill_missing_slots => .
 4. 0 (volume=0) => .

 (NEW - FREEZE AFTER FIRST SUCCESS):
 5. The original fill_gap_once algorithm is left intact. The ONLY new thing
    is a persistent freeze flag in the SQLite candle store (gap_state.filled).
    Once a successful fill has run for an asset, the flag is set to 1 and
    every subsequent call to fill_gap_once returns immediately without
    touching the candles. This preserves the candles exactly as they were
    after the first fill - no flicker, no replacement of closed candles.
    A 'full re-fetch' command can clear the flag and force a new fill.

 Args:
 client: Quotex
 asset_obj: Asset ( api_symbol symbol)
 period: MT4 timeframe (PERIOD=1 for M1)
 """
        api_symbol = asset_obj.api_symbol
        derived_symbol = asset_obj.symbol

        # 0) FREEZE CHECK: if a successful fill already happened for this asset
        # (gap_state.filled == 1 in the SQLite store), do NOT touch the candles
        # at all. This is the entire fix for the 'candles flicker' symptom -
        # the original algorithm is preserved 1:1, we only skip it after the
        # first successful run.
        try:
            is_filled, _last_at = self.candle_store.is_gap_filled(derived_symbol)
            if is_filled:
                return    # frozen - keep candles exactly as they were
        except Exception:
            pass

        # 1) skip if filled recently (within GAP_FILL_REFRESH_INTERVAL)
        now_ts = time.time()
        last_fill = self._gap_filled_at.get(derived_symbol, 0)
        already_filled = self._gap_filled.get(derived_symbol, False)
        if already_filled and (now_ts - last_fill) < GAP_FILL_REFRESH_INTERVAL:
            return

        # 2) sync_state asset_obj.candles
        if derived_symbol not in self.sync_state:
            if not asset_obj.candles:
                # try to load from store first
                snap = self.load_snapshot(derived_symbol)
                if snap:
                    asset_obj.candles = snap
                else:
                    return
            self.sync_state[derived_symbol] = {
                'period': period,
                'candles': list(asset_obj.candles),
                'last_write': 0,
                'last_price': float(asset_obj.candles[-1]['close']) if asset_obj.candles else 0.0,
            }
        state = self.sync_state[derived_symbol]
        if not state['candles']:
            return

        try:
            # Fetch last GAP_FILL_CANDLES (10) recent candles to replace incomplete ones
            small_days = (GAP_FILL_CANDLES * PERIOD_SECONDS) / 86400.0
            candles = await client.get_candles(api_symbol, time.time(), int(small_days * 86400), PERIOD_SECONDS)
            if not candles:
                # Fill existing gaps even without new data
                merged = sorted(state['candles'], key=lambda x: x['time'])[-INITIAL_CANDLES:]
                merged = _fill_missing_slots(merged, PERIOD_SECONDS, max_gap=1440)
                state['candles'] = merged
                self.write_to_file(derived_symbol, period, merged)
                asset_obj.candles = merged
                self._gap_filled[derived_symbol] = True
                self._gap_filled_at[derived_symbol] = now_ts
                self.save_snapshot(derived_symbol, merged)
                # mark as permanently filled in the DB so the next cycle skips
                self.candle_store.set_gap_filled(derived_symbol, True, now_ts)
                return

            # Build candle_map: replace incomplete closed candles with real API data
            # - Current streaming candle (time >= current_period_start): SKIP (streaming handles it)
            # - Closed candles in the fetched range: REPLACE with real data (fixes small bodies)
            # - Missing candles: ADD them
            # - Synthetic candles (volume=0): REPLACE with real data
            current_period_start = _align_time(int(time.time()))
            candle_map: Dict[int, dict] = {}
            for c in state['candles']:
                candle_map[c['time']] = c
            new_count = 0
            replaced_count = 0
            for c in candles:
                t = _align_time(int(c.get('time', c.get('timestamp', 0))))
                o = float(c.get('open', c.get('o', 0)) or 0)
                h = float(c.get('high', c.get('max', c.get('h', 0))) or 0)
                l = float(c.get('low', c.get('min', c.get('l', 0))) or 0)
                cl = float(c.get('close', c.get('c', 0)) or 0)
                v = int(c.get('volume', c.get('vol', 0)) or 0)
                if o > 0 and h > 0 and l > 0 and cl > 0:
                    existing = candle_map.get(t)
                    if existing is None:
                        # genuinely missing candle (real gap) - add it
                        candle_map[t] = {
                            'time': t, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': v,
                        }
                        new_count += 1
                    elif t >= current_period_start:
                        # current streaming candle - DON'T TOUCH (streaming handles it)
                        continue
                    else:
                        # closed candle in the fetched range - REPLACE with real data
                        # (fixes small/incomplete bodies from partial streaming)
                        candle_map[t] = {
                            'time': t, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': v,
                        }
                        replaced_count += 1

            # sort + limit to INITIAL_CANDLES
            merged = sorted(candle_map.values(), key=lambda x: x['time'])[-INITIAL_CANDLES:]
            # fill remaining gaps with flat candles (max_gap=1440 = full day)
            merged = _fill_missing_slots(merged, PERIOD_SECONDS, max_gap=1440)
            state['candles'] = merged

            # write HST
            self.write_to_file(derived_symbol, period, merged)

            # update asset_obj.candles (for live price display)
            asset_obj.candles = merged
            if merged:
                asset_obj.price = merged[-1]['close']

            # 9) mark gap as filled
            self._gap_filled[derived_symbol] = True
            self._gap_filled_at[derived_symbol] = now_ts
            # 10) persist candles to the SQLite store (so the next restart
            # loads them from the DB instead of re-fetching from the API).
            self.save_snapshot(derived_symbol, merged)
            # 11) set the permanent freeze flag - subsequent fill_gap_once
            # calls for this asset will return immediately without touching
            # the candles. This is the entire fix for the 'flicker' symptom.
            self.candle_store.set_gap_filled(derived_symbol, True, now_ts)
        except Exception as e:
            err_str = str(e).lower()
            if not any(x in err_str for x in ['winerror', 'permission', 'access', 'closed', 'connection']):
                pass

MT4_WRITER = MT4Writer()

async def mt4_gap_filler():
    global GAP_FILL_SUMMARY, GAP_FILL_ACTIVE
    # Skip entirely for subsecond mode — no gap filler for 5s/10s/15s/30s
    if IS_SUBSECOND:
        GAP_FILL_SUMMARY = "GAP FILL: disabled (subsecond mode)"
        GAP_FILL_ACTIVE = False
        return
    total = len(ALL_STREAMING_ASSETS)
    GAP_FILL_SUMMARY = f"GAP FILL: waiting 60s before starting ({total} assets)..."
    await asyncio.sleep(60)
    cycle = 0
    while True:
        cycle += 1
        if not ALL_STREAMING_ASSETS:
            GAP_FILL_SUMMARY = "GAP FILL: no assets to fill"
            GAP_FILL_ACTIVE = False
            await asyncio.sleep(GAP_FILL_REFRESH_INTERVAL)
            continue
        GAP_FILL_ACTIVE = True
        filled_count = 0
        skipped_count = 0
        failed_count = 0
        failed_assets = []
        t0 = time.time()
        for i, asset in enumerate(ALL_STREAMING_ASSETS, 1):
            if not CLIENT or not CLIENT.api:
                GAP_FILL_SUMMARY = f"GAP FILL: ABORTED (connection lost) | {filled_count}/{total} filled | {skipped_count} skipped"
                GAP_FILL_ACTIVE = False
                await asyncio.sleep(5)
                break
            try:
                await MT4_WRITER.fill_gap_once(CLIENT, asset, PERIOD)
                if MT4_WRITER._gap_filled.get(asset.symbol, False):
                    filled_count += 1
                else:
                    skipped_count += 1
                await asyncio.sleep(0.3)
            except Exception:
                skipped_count += 1
                failed_count += 1
                failed_assets.append(asset.symbol)
            # live progress update in banner
            GAP_FILL_SUMMARY = (
                f"GAP FILL c{cycle}: {i}/{total} done | {filled_count} filled | "
                f"{skipped_count} skipped | {failed_count} failed | {time.time()-t0:.1f}s"
            )
        else:
            # loop completed normally (no connection loss break)
            elapsed = time.time() - t0
            fail_str = f" | Failed: {', '.join(failed_assets[:5])}" if failed_assets else ""
            GAP_FILL_SUMMARY = (
                f"GAP FILL c{cycle}: COMPLETE in {elapsed:.1f}s | {filled_count}/{total} filled | "
                f"{skipped_count} skipped{fail_str} | next in {GAP_FILL_REFRESH_INTERVAL}s"
            )
            GAP_FILL_ACTIVE = False
            await asyncio.sleep(GAP_FILL_REFRESH_INTERVAL)
            total = len(ALL_STREAMING_ASSETS)
            continue
        # reached here only on connection loss (break)
        GAP_FILL_ACTIVE = False
        await asyncio.sleep(GAP_FILL_REFRESH_INTERVAL)
        total = len(ALL_STREAMING_ASSETS)


WEB_PUSH_INTERVAL = 30  # seconds between full candle re-push to web dashboard

async def web_candle_refresher():
    """Every 30 seconds: re-fetch full candle history for ALL streaming assets
    and push to the web dashboard so the chart always shows fresh, complete data.
    Uses the same fetch_candles_with_retry path as the initial load.
    Skips assets if connection is down (retries next cycle).
    """
    global GAP_FILL_SUMMARY
    # Wait for initial load to complete before first push
    await asyncio.sleep(35)
    cycle = 0
    while True:
        cycle += 1
        assets = list(ALL_STREAMING_ASSETS)
        total = len(assets)
        if total == 0 or not CONNECTION_ALIVE or CLIENT is None:
            GAP_FILL_SUMMARY = f"WEB PUSH c{cycle}: waiting for connection... (next in {WEB_PUSH_INTERVAL}s)"
            await asyncio.sleep(WEB_PUSH_INTERVAL)
            continue

        pushed = 0
        skipped = 0
        t0 = time.time()
        GAP_FILL_SUMMARY = f"WEB PUSH c{cycle}: refreshing {total} assets..."

        for asset in assets:
            if not CONNECTION_ALIVE or CLIENT is None:
                GAP_FILL_SUMMARY = f"WEB PUSH c{cycle}: ABORTED (connection lost) — {pushed}/{total} pushed"
                skipped = total - pushed
                break
            try:
                candles_count, _ = await fetch_candles_with_retry(
                    asset, max_retries=3, idx=pushed+1, total=total
                )
                if candles_count > 0:
                    try:
                        _web_update_asset(asset, full_resync=True)
                    except Exception:
                        pass
                    pushed += 1
                else:
                    skipped += 1
            except Exception:
                skipped += 1
            # Small delay between assets to avoid hammering the server
            await asyncio.sleep(0.2)

        elapsed = time.time() - t0
        GAP_FILL_SUMMARY = (
            f"WEB PUSH c{cycle}: {pushed}/{total} pushed ({elapsed:.1f}s) | "
            f"{skipped} skipped | next in {WEB_PUSH_INTERVAL}s"
        )
        await asyncio.sleep(WEB_PUSH_INTERVAL)

def print_dashboard():
    _tf_label = "Unknown"
    for tf_tuple in TIMEFRAMES:
        mt4_p, secs, label = tf_tuple[0], tf_tuple[1], tf_tuple[2]
        if mt4_p == PERIOD and secs == PERIOD_SECONDS:
            _tf_label = label
            break
    # تبسيط العنوان: سطر واحد فاصل بدل 3 خطوط زرقاء كثيفة
    print(f"  {Colors.DIM}{'─'*68}{Colors.RESET}")
    print(f"  {Colors.BOLD}QXChartMT4 Pro - v8.0  {Colors.DIM}|  @qxzero1  |  2026{Colors.RESET}")
    print(f"  {Colors.DIM}{'─'*68}{Colors.RESET}")
    print(f"  {Colors.CYAN}Timeframe  {Colors.RESET}: {_tf_label} ({PERIOD_SECONDS}s)")
    print(f"  {Colors.CYAN}History    {Colors.RESET}: {HISTORY_DAYS:.2f} day = {INITIAL_CANDLES} candles")
    # FIX L11: TZ offset display
    _tz_sec = _get_tz_offset()
    _tz_sign = '+' if _tz_sec >= 0 else '-'
    _tz_h, _tz_m = divmod(abs(_tz_sec) // 60, 60)
    _tz_src = "manual" if LOCAL_TZ_OFFSET_SECONDS is not None else "system"
    print(f"  {Colors.CYAN}TZ offset  {Colors.RESET}: UTC{_tz_sign}{_tz_h:02d}:{_tz_m:02d} (source={_tz_src})")
    print(f"  {Colors.CYAN}Gap fill   {Colors.RESET}: {GAP_FILL_CANDLES} candles / {GAP_FILL_REFRESH_INTERVAL}s")
    print(f"  {Colors.GREEN}Contact    {Colors.RESET}: https://t.me/qxchart")
    print(f"  {Colors.DIM}{'─'*68}{Colors.RESET}\n")

# ==============================================================================
# WEB SERVER — Live chart dashboard (ap.py style, embedded)
# Runs on http://localhost:8765  — pairs click -> live chart
# ==============================================================================
WEB_SERVER_PORT = 8765
WEB_SERVER_HOST = "127.0.0.1"

# Shared candle store for web server (populated by realtime_stream + fetch)
_web_candle_store = {}          # pair_name -> {"candles": [...], "lastUpdate": ms, "digits": int}
_web_candle_lock = threading.RLock()
_web_push_stats = {"total_pushes": 0, "last_push_time": 0, "start_time": time.time()}

def _web_pair_name(api_symbol):
    """Convert api_symbol (e.g. AUDCAD_otc) -> display pair name (AUDCAD-OTCq)."""
    s = api_symbol.strip()
    if s.lower().endswith("_otc"):
        return s[:-4].upper() + "-OTCq"
    return s.upper()

_web_latest_tick = {}   # pair_name -> {"price": float, "time": int, "digits": int, "ts": ms}

def _web_update_asset(asset, full_resync=False):
    """Called after every candle update -- pushes data to web candle store.

    v9.0: OPTIMIZED for max-speed live ticks.
      - Default (full_resync=False): only updates _web_latest_tick (cheap, ~1µs).
        Used by realtime_stream on every tick. Does NOT copy the full candle list.
      - full_resync=True: refreshes the full _web_candle_store[pair] entry.
        Used after initial historical fetch and on candle close (new candle started).
    """
    if not asset.candles:
        return
    pair = _web_pair_name(asset.api_symbol)
    try:
        digits = asset.digits(asset.price) if asset.price else 5
    except Exception:
        digits = 5
    last_c = asset.candles[-1]
    now_ms = int(time.time() * 1000)

    # Always update the lightweight tick cache (fast path for /api/last-tick).
    # This is what the chart polls at 50ms — must be O(1).
    with _web_candle_lock:
        _web_latest_tick[pair] = {
            "price": float(asset.price) if asset.price else float(last_c.get("close", 0)),
            "time": int(last_c.get("time", 0)),
            "open": float(last_c.get("open", 0)),
            "high": float(last_c.get("high", 0)),
            "low": float(last_c.get("low", 0)),
            "close": float(last_c.get("close", 0)),
            "digits": digits,
            "ts": now_ms,
        }
        _web_push_stats["total_pushes"] += 1
        _web_push_stats["last_push_time"] = now_ms

    # Only do the heavy full-candle copy when explicitly requested.
    # realtime_stream calls _web_update_asset(asset, full_resync=True) only on
    # candle CLOSE (new candle started), not on every tick.
    if full_resync:
        candles_copy = [dict(c) for c in asset.candles[-3000:]]
        with _web_candle_lock:
            _web_candle_store[pair] = {
                "pair": pair,
                "digits": digits,
                "candles": candles_copy,
                "lastUpdate": now_ms,
            }

# == HTML & CSS (same dark theme as ap.py) =====================================
_WEB_SHARED_CSS = """
:root{--bg-primary:#0a0e17;--bg-secondary:#111827;--bg-nav:#0d1117;
      --border:#1f2937;--text:#e5e7eb;--text-dim:#9ca3af;--text-muted:#6b7280;
      --green:#22c55e;--red:#ef4444;--blue:#3b82f6;--accent:#6366f1;}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:var(--bg-primary);color:var(--text);min-height:100vh;}
a{color:var(--blue);text-decoration:none;}
a:hover{text-decoration:underline;}
"""

_WEB_HOME_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0,user-scalable=yes">
<meta name="theme-color" content="#0a0e17">
<title>QXChart MT4 - Live Dashboard</title>
<style>
CSS_HERE
.header{background:var(--bg-nav);border-bottom:1px solid var(--border);
        padding:16px 24px;display:flex;align-items:center;justify-content:space-between;
        position:sticky;top:0;z-index:50;}
.logo{display:flex;align-items:center;gap:12px;}
.logo-icon{width:40px;height:40px;border-radius:12px;
           background:linear-gradient(135deg,#22c55e,#06b6d4);
           display:flex;align-items:center;justify-content:center;
           font-weight:bold;color:#000;font-size:18px;}
.logo h1{font-size:20px;font-weight:700;}
.logo p{font-size:12px;color:var(--text-muted);}
.status-badge{display:flex;align-items:center;gap:8px;
              padding:6px 12px;border-radius:20px;background:rgba(255,255,255,0.05);}
.status-dot{width:8px;height:8px;border-radius:50%;}
.status-dot.live{background:var(--green);animation:pulse 2s infinite;}
.status-dot.offline{background:var(--red);}
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.4;}}
.status-text{font-size:12px;color:var(--text-dim);}
.main{max-width:1200px;margin:0 auto;padding:24px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
            gap:12px;margin-bottom:24px;}
.stat-card{background:var(--bg-secondary);border:1px solid var(--border);
           border-radius:12px;padding:16px;}
.stat-card .label{font-size:11px;color:var(--text-muted);margin-bottom:4px;}
.stat-card .value{font-size:24px;font-weight:700;}
.stat-card .value.green{color:var(--green);}
.stat-card .value.red{color:var(--red);}
.search-box{position:relative;margin-bottom:24px;}
.search-box input{width:100%;padding:12px 16px 12px 44px;background:var(--bg-secondary);
                  border:1px solid var(--border);border-radius:12px;color:var(--text);
                  font-size:14px;outline:none;transition:border-color 0.2s;}
.search-box input:focus{border-color:var(--blue);}
.search-box svg{position:absolute;left:14px;top:50%;transform:translateY(-50%);
                width:20px;height:20px;color:var(--text-muted);}
.pairs-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;}
.pair-card{background:var(--bg-secondary);border:1px solid var(--border);
           border-radius:12px;padding:16px;cursor:pointer;
           transition:all 0.2s;display:flex;align-items:center;justify-content:space-between;}
.pair-card:hover{background:#162032;border-color:rgba(59,130,246,0.5);transform:translateY(-1px);}
.pair-left{display:flex;align-items:center;gap:12px;}
.pair-flag{font-size:24px;}
.pair-name{font-weight:600;font-size:15px;}
.pair-detail{font-size:12px;color:var(--text-muted);}
.pair-right{text-align:right;}
.pair-status{font-size:11px;padding:2px 8px;border-radius:10px;display:inline-flex;
             align-items:center;gap:4px;margin-bottom:4px;}
.pair-status.live{background:rgba(34,197,94,0.1);color:var(--green);}
.pair-status.stale{background:rgba(239,68,68,0.1);color:var(--red);}
.pair-status .dot{width:6px;height:6px;border-radius:50%;display:inline-block;}
.pair-status.live .dot{background:var(--green);}
.pair-status.stale .dot{background:var(--red);}
.pair-time{font-size:11px;color:var(--text-muted);}
.empty-state{text-align:center;padding:60px 24px;}
.empty-state h3{font-size:20px;margin-bottom:8px;}
.empty-state p{color:var(--text-dim);font-size:14px;max-width:400px;margin:0 auto;}
.footer{border-top:1px solid var(--border);background:var(--bg-nav);padding:16px 24px;margin-top:32px;}
.footer-inner{max-width:1200px;margin:0 auto;display:flex;
              justify-content:space-between;font-size:12px;color:var(--text-muted);flex-wrap:wrap;gap:8px;}
@media(max-width:640px){
  .header{padding:12px 16px;flex-wrap:wrap;gap:8px;}
  .logo h1{font-size:16px;}.logo p{font-size:11px;}
  .main{padding:16px;}
  .pairs-grid{grid-template-columns:1fr;}
  .stats-grid{grid-template-columns:repeat(2,1fr);}
  .pair-card{padding:12px;}
}
</style>
</head>
<body>
<div class="header">
  <div class="logo">
    <div class="logo-icon">Q</div>
    <div><h1>QXChart MT4 Pro</h1><p>Live Quotex OTC Chart Dashboard</p></div>
  </div>
  <div class="status-badge">
    <span class="status-dot offline" id="statusDot"></span>
    <span class="status-text" id="statusText">Connecting...</span>
  </div>
</div>
<div class="main">
  <div class="stats-grid">
    <div class="stat-card"><div class="label">Active Pairs</div><div class="value" id="statPairs">0</div></div>
    <div class="stat-card"><div class="label">Total Pushes</div><div class="value" id="statPushes">0</div></div>
    <div class="stat-card"><div class="label">Last Push</div><div class="value" id="statLastPush">Never</div></div>
    <div class="stat-card"><div class="label">Status</div><div class="value red" id="statStatus">OFFLINE</div></div>
  </div>
  <div class="search-box">
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
    <input type="text" id="searchInput" placeholder="Search pairs... (e.g. USD, EUR, BDT)">
  </div>
  <div class="pairs-grid" id="pairsGrid"></div>
  <div class="empty-state" id="emptyState" style="display:none;">
    <h3>No Data Yet</h3>
    <p>Waiting for candle data from Quotex... The script is fetching history for all pairs.</p>
  </div>
</div>
<div class="footer">
  <div class="footer-inner">
    <span>QXChart MT4 Pro - Live Dashboard &copy; 2026</span>
    <span>Pairs refresh every 3s &bull; Chart updates every 1s</span>
  </div>
</div>
<script>
const FLAGS={USD:"\u{1F1FA}\u{1F1F8}",EUR:"\u{1F1EA}\u{1F1FA}",GBP:"\u{1F1EC}\u{1F1E7}",JPY:"\u{1F1EF}\u{1F1F5}",AUD:"\u{1F1E6}\u{1F1FA}",NZD:"\u{1F1F3}\u{1F1FF}",CAD:"\u{1F1E8}\u{1F1E6}",CHF:"\u{1F1E8}\u{1F1ED}",BDT:"\u{1F1E7}\u{1F1E9}",ARS:"\u{1F1E6}\u{1F1F7}",INR:"\u{1F1EE}\u{1F1F3}",MXN:"\u{1F1F2}\u{1F1FD}",PHP:"\u{1F1F5}\u{1F1ED}",PKR:"\u{1F1F5}\u{1F1F0}",NGN:"\u{1F1F3}\u{1F1EC}",COP:"\u{1F1E8}\u{1F1F4}",IDR:"\u{1F1EE}\u{1F1E9}",EGP:"\u{1F1EA}\u{1F1EC}",DZD:"\u{1F1E9}\u{1F1FF}",BRL:"\u{1F1E7}\u{1F1F7}",ZAR:"\u{1F1FF}\u{1F1E6}"};
function getFlag(pair){const base=pair.replace(/-OTCq?$/,"").replace(/[-_].*$/,"");const codes=Object.keys(FLAGS).sort((a,b)=>b.length-a.length);let rem=base,f=[];for(const c of codes){if(rem.startsWith(c)){f.push(FLAGS[c]);rem=rem.slice(c.length);}}return f.join("")||"\u{1F4B1}";}
function cleanName(p){return p.replace("-OTCq"," (OTC)").replace("-OTC"," (OTC)");}
function timeSince(ts){if(!ts)return"Never";const d=Math.floor((Date.now()-ts)/1000);if(d<3)return"Just now";if(d<60)return d+"s ago";if(d<3600)return Math.floor(d/60)+"m ago";return Math.floor(d/3600)+"h ago";}
async function loadPairs(){
  try{
    const r=await fetch("/api/pairs",{cache:"no-store"});
    const d=await r.json();
    if(d.status==="OK"){
      const pairs=d.pairs||[];const stats=d.stats||{};
      document.getElementById("statPairs").textContent=pairs.length;
      document.getElementById("statPushes").textContent=(stats.totalPushes||0).toLocaleString();
      document.getElementById("statLastPush").textContent=timeSince(stats.lastPushTime);
      const isLive=stats.isLive;
      document.getElementById("statusDot").className="status-dot "+(isLive?"live":"offline");
      document.getElementById("statusText").textContent=isLive?"LIVE":"Waiting for data...";
      const sv=document.getElementById("statStatus");
      sv.textContent=isLive?"LIVE":"OFFLINE";sv.className="value "+(isLive?"green":"red");
      const search=document.getElementById("searchInput").value.toLowerCase();
      const filtered=pairs.filter(p=>p.pair.toLowerCase().includes(search));
      const grid=document.getElementById("pairsGrid");
      const empty=document.getElementById("emptyState");
      if(pairs.length===0){grid.innerHTML="";empty.style.display="block";return;}
      empty.style.display="none";
      if(filtered.length===0&&search){grid.innerHTML='<div style="text-align:center;padding:40px;color:var(--text-dim);">No pairs matching "'+search+'"</div>';return;}
      grid.innerHTML=filtered.map(p=>{
        const live=Date.now()-p.lastUpdate<10000;
        return '<a href="/pairs='+encodeURIComponent(p.pair)+'" class="pair-card">'
          +'<div class="pair-left"><span class="pair-flag">'+getFlag(p.pair)+'</span>'
          +'<div><div class="pair-name">'+cleanName(p.pair)+'</div>'
          +'<div class="pair-detail">'+(p.candleCount||0)+' candles</div></div></div>'
          +'<div class="pair-right">'
          +'<div class="pair-status '+(live?"live":"stale")+'"><span class="dot"></span>'+(live?"Live":"Stale")+'</div>'
          +'<div class="pair-time">'+timeSince(p.lastUpdate)+'</div></div></a>';
      }).join("");
    }
  }catch(e){console.error(e);}
}
loadPairs();
setInterval(loadPairs,3000);
document.getElementById("searchInput").addEventListener("input",loadPairs);
</script>
</body>
</html>"""

_WEB_CHART_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0,user-scalable=yes,viewport-fit=cover">
<meta name="theme-color" content="#0a0e17">
<title>PAIR_DISPLAY - Live Chart | QXChart MT4</title>
<!-- ===== Lightweight Charts (TradingView) ~45KB, no jQuery/React ===== -->
<script src="https://unpkg.com/lightweight-charts@4.1.3/dist/lightweight-charts.standalone.production.js"></script>
<style>
CSS_HERE
html,body{height:100%;width:100%;overflow:hidden;}
body{height:100vh;display:flex;flex-direction:column;overflow:hidden;}
.nav{display:flex;align-items:center;gap:10px;padding:10px 16px;
     background:var(--bg-nav);border-bottom:1px solid var(--border);flex-shrink:0;}
.nav-back{color:var(--text-dim);display:flex;text-decoration:none;}
.nav-back:hover{color:#fff;}
.nav-sep{width:1px;height:16px;background:var(--border);}
.nav-brand{font-size:13px;color:var(--text-dim);}
.chart-header{display:flex;align-items:center;padding:12px 16px;
              background:var(--bg-nav);border-bottom:1px solid var(--border);
              flex-shrink:0;flex-wrap:wrap;gap:8px 16px;}
.chart-header-left{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;flex:1;}
.pair-title{font-size:18px;font-weight:700;white-space:nowrap;}
.current-price{font-size:24px;font-weight:700;font-family:'SF Mono','Fira Code',monospace;white-space:nowrap;transition:color 300ms ease;}
.price-change{font-size:13px;font-weight:600;font-family:monospace;white-space:nowrap;}
.price-change.up{color:var(--green);}
.price-change.down{color:var(--red);}
.chart-wrap{flex:1;position:relative;background:var(--bg-primary);min-height:0;width:100%;overflow:hidden;}
#chartContainer{position:absolute;inset:0;width:100%;height:100%;}
.overlay{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
         background:rgba(10,14,23,0.92);z-index:10;}
.overlay-box{text-align:center;padding:24px;max-width:400px;}
.spinner{width:48px;height:48px;border:3px solid var(--blue);border-top-color:transparent;
         border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 16px;}
@keyframes spin{to{transform:rotate(360deg);}}
.overlay p{font-size:14px;color:var(--text-dim);}
@media(max-width:380px){.nav{padding:6px 10px;}.chart-header{padding:8px 10px;}.pair-title{font-size:14px;}.current-price{font-size:18px;}}
@media(max-width:600px){.pair-title{font-size:16px;}.current-price{font-size:20px;}}
</style>
</head>
<body>
<div class="nav">
  <a href="/" class="nav-back"><svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg></a>
  <div class="nav-sep"></div>
  <span class="nav-brand">QXChart MT4 Pro</span>
</div>
<div class="chart-header">
  <div class="chart-header-left">
    <span class="pair-title" id="pairTitle">PAIR_DISPLAY</span>
    <span class="current-price" id="currentPrice">---</span>
    <span class="price-change" id="priceChange"></span>
  </div>
</div>
<div class="chart-wrap">
  <div id="chartContainer"></div>
  <div class="overlay" id="loadingOverlay">
    <div class="overlay-box">
      <div class="spinner"></div>
      <p>Loading chart data...</p>
    </div>
  </div>
</div>
<script>
// ===== Lightweight Charts (TradingView) — Same dark theme as the rest of the app =====
const PAIR_NAME = "PAIR_NAME_RAW";
let candles = [];       // [{t, open, high, low, close}]
let digits = 5;
let lastBarTime = 0;     // last candle time we fed to the series (for series.update)
let initialized = false;

// Colors (match the existing palette)
const C = {
  bg:"#0a0e17", grid:"#1a2235", up:"#22c55e", down:"#ef4444",
  text:"#9ca3af", textBright:"#e5e7eb", crosshair:"rgba(255,255,255,0.3)",
  border:"#1f2937"
};

// ===== Create chart =====
const container = document.getElementById("chartContainer");
const chart = LightweightCharts.createChart(container, {
  layout: {
    background: { type: 'solid', color: C.bg },
    textColor: C.text,
    fontSize: 11,
    fontFamily: "'SF Mono','Fira Code',monospace"
  },
  grid: {
    vertLines: { color: C.grid, style: 1 },
    horzLines: { color: C.grid, style: 1 }
  },
  crosshair: {
    mode: LightweightCharts.CrosshairMode.Normal,
    vertLine: { color: C.crosshair, width: 1, style: 2, labelBackgroundColor: "#3b82f6" },
    horzLine: { color: C.crosshair, width: 1, style: 2, labelBackgroundColor: "#3b82f6" }
  },
  rightPriceScale: {
    borderColor: C.border,
    scaleMargins: { top: 0.08, bottom: 0.08 }
  },
  timeScale: {
    borderColor: C.border,
    timeVisible: true,
    secondsVisible: false,
    rightOffset: 4,
    barSpacing: 8
  },
  handleScroll: true,
  handleScale: true,
  autoSize: true
});

// ===== Candlestick series =====
const series = chart.addCandlestickSeries({
  upColor: C.up,
  downColor: C.down,
  borderUpColor: C.up,
  borderDownColor: C.down,
  wickUpColor: C.up,
  wickDownColor: C.down,
  borderVisible: false,
  priceFormat: { type: 'price', precision: digits, minMove: 0.00001 }
});

// Current price line (dashed, colored by last candle direction)
const priceLine = series.createPriceLine({
  price: 0,
  color: C.up,
  lineWidth: 1,
  lineStyle: LightweightCharts.LineStyle.Dashed,
  axisLabelVisible: true,
  title: ''
});

// ===== Helpers =====
function fmtPrice(p){ return Number(p).toFixed(digits); }

function updatePriceLine(){
  if(candles.length === 0) return;
  const last = candles[candles.length - 1];
  const isUp = last.close >= last.open;
  // Remove and recreate to update color (Lightweight Charts limitation)
  series.removePriceLine(priceLine);
  const newLine = series.createPriceLine({
    price: last.close,
    color: isUp ? C.up : C.down,
    lineWidth: 1,
    lineStyle: LightweightCharts.LineStyle.Dashed,
    axisLabelVisible: true,
    title: ''
  });
  // Replace reference (we re-declare via the variable name)
  // Note: cannot reassign const, so we keep using a function-local approach below
}

function refreshPriceLine(){
  if(candles.length === 0) return;
  const last = candles[candles.length - 1];
  const isUp = last.close >= last.open;
  // Simpler: remove all price lines and add a new one each tick
  // (Lightweight Charts does not allow updating an existing price line in place)
  // We track it via a module-level variable
  if(window._activePriceLine){
    try { series.removePriceLine(window._activePriceLine); } catch(e){}
  }
  window._activePriceLine = series.createPriceLine({
    price: last.close,
    color: isUp ? C.up : C.down,
    lineWidth: 1,
    lineStyle: LightweightCharts.LineStyle.Dashed,
    axisLabelVisible: true,
    title: ''
  });
}

function updatePriceHeader(){
  if(!candles || candles.length === 0) return;
  const last = candles[candles.length - 1];
  const first = candles[0];
  const priceEl = document.getElementById("currentPrice");
  const changeEl = document.getElementById("priceChange");
  const newP = Number(last.close).toFixed(digits);
  if(priceEl){
    if(priceEl.textContent !== newP && priceEl.textContent !== "---"){
      priceEl.style.color = last.close >= last.open ? "#22c55e" : "#ef4444";
      setTimeout(() => { priceEl.style.color = ""; }, 300);
    }
    priceEl.textContent = newP;
  }
  if(changeEl){
    const change = last.close - first.open;
    const pct = first.open > 0 ? (change / first.open * 100) : 0;
    const sign = change >= 0 ? "+" : "";
    changeEl.textContent = sign + change.toFixed(digits) + " (" + sign + pct.toFixed(2) + "%)";
    changeEl.className = "price-change " + (change >= 0 ? "up" : "down");
  }
  refreshPriceLine();
}

// ===== Data fetching =====
async function fetchFullCandles(){
  try{
    const r = await fetch("/api/candles?pair=" + encodeURIComponent(PAIR_NAME), {cache:"no-store"});
    if(!r.ok) return;
    const data = await r.json();
    if(data.status === "OK" && data.candles && data.candles.length > 0){
      digits = data.digits || 5;
      // Update price format precision
      series.applyOptions({ priceFormat: { type: 'price', precision: digits, minMove: Math.pow(10, -digits) } });
      // Normalize: API sends {t, open, high, low, close}
      // Lightweight Charts expects {time, open, high, low, close}
      let raw = data.candles.map(c => ({
        time: Number(c.t || c.time || 0),
        open: Number(c.open), high: Number(c.high),
        low: Number(c.low), close: Number(c.close)
      })).filter(c => c.time > 0 && c.open > 0);
      raw.sort((a,b) => a.time - b.time);
      // Deduplicate by time (Lightweight Charts requires strictly ascending unique times)
      const seen = new Set();
      raw = raw.filter(c => { if(seen.has(c.time)) return false; seen.add(c.time); return true; });

      candles = raw;
      if(candles.length > 0){
        lastBarTime = candles[candles.length - 1].time;
      }

      // Push to series
      series.setData(candles);

      // Hide loading overlay
      const ol = document.getElementById("loadingOverlay");
      if(ol && candles.length > 0) ol.style.display = "none";

      // Fit content on first load, then keep the latest view
      if(!initialized){
        chart.timeScale().fitContent();
        initialized = true;
      }

      updatePriceHeader();
    }
  } catch(e){ console.error("[Chart] fetch error:", e); }
}

async function fetchLiveTick(){
  try{
    const r = await fetch("/api/last-tick?pair=" + encodeURIComponent(PAIR_NAME), {cache:"no-store"});
    if(!r.ok) return;
    const d = await r.json();
    if(d.status === "OK" && d.time && d.open){
      const t = Number(d.time);
      const tick = {
        time: t, open: Number(d.open), high: Number(d.high),
        low: Number(d.low), close: Number(d.close)
      };
      if(t > 0 && tick.open > 0 && candles.length > 0){
        const last = candles[candles.length - 1];
        if(t === last.time){
          // Update current candle in place
          last.high = Math.max(last.high, tick.high);
          last.low = Math.min(last.low, tick.low);
          last.close = tick.close;
          series.update(last);
        } else if(t > last.time){
          candles.push(tick);
          lastBarTime = t;
          series.update(tick);
        }
        updatePriceHeader();
      }
    }
  } catch(e){}
}

// Start
fetchFullCandles();
// v9.0: MAX-SPEED polling intervals.
//   - fetchLiveTick: 300ms -> 50ms (20 ticks/sec, near-instant chart updates)
//     This is the hot path: the dashboard polls /api/last-tick for the live price.
//   - fetchFullCandles: 3000ms -> 500ms (rare full resync; the live tick path
//     handles 99% of updates). 500ms is enough to catch missed candles without
//     hammering the Flask server.
// Note: these are CLIENT-side polls to the local Flask server. The Flask server
// itself receives updates from realtime_stream at STREAM_POLL_INTERVAL=0.05s.
setInterval(fetchFullCandles, 500);
setInterval(fetchLiveTick, 50);
</script>
</body>
</html>"""

# == Flask Web Server ==========================================================
def _build_web_flask_app():
    """Build and return Flask app for the embedded web server."""
    if not HAS_FLASK:
        return None

    web_app = Flask(__name__)

    @web_app.route("/")
    def web_home():
        html = _WEB_HOME_HTML.replace("CSS_HERE", _WEB_SHARED_CSS)
        return Response(html, content_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store, no-cache"})

    @web_app.route("/pairs=<path:pair_name>")
    def web_pair_chart(pair_name):
        pair_name = pair_name.strip()
        display = pair_name.replace("-OTCq", " (OTC)").replace("-OTC", " (OTC)")
        html = _WEB_CHART_HTML.replace("PAIR_NAME_RAW", pair_name)
        html = html.replace("PAIR_DISPLAY", display)
        html = html.replace("CSS_HERE", _WEB_SHARED_CSS)
        return Response(html, content_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store, no-cache"})

    @web_app.route("/api/pairs")
    def web_api_pairs():
        with _web_candle_lock:
            pairs_data = []
            for name, data in sorted(_web_candle_store.items()):
                pairs_data.append({
                    "pair": name,
                    "lastUpdate": data.get("lastUpdate", 0),
                    "candleCount": len(data.get("candles", [])),
                })
        last_push = _web_push_stats.get("last_push_time", 0)
        is_live = last_push > 0 and (int(time.time() * 1000) - last_push) < 10000
        result = {
            "status": "OK",
            "pair_count": len(pairs_data),
            "pairs": pairs_data,
            "stats": {
                "totalPushes": _web_push_stats.get("total_pushes", 0),
                "lastPushTime": last_push,
                "isLive": is_live,
            },
        }
        resp = Response(json.dumps(result, separators=(",", ":")),
                        content_type="application/json")
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    @web_app.route("/api/candles")
    def web_api_candles():
        pair = flask_request.args.get("pair", "").strip()
        if not pair:
            return Response(json.dumps({"status": "ERROR", "error": "Missing pair", "candles": []}),
                            content_type="application/json", status=400)
        with _web_candle_lock:
            data = _web_candle_store.get(pair)
            if data is None:
                pair_lower = pair.lower()
                for k, v in _web_candle_store.items():
                    if k.lower() == pair_lower:
                        data = v
                        break
        if data is None:
            return Response(json.dumps({"status": "ERROR", "error": f"No data for {pair}", "candles": []}),
                            content_type="application/json", status=404)
        candles = data.get("candles", [])
        chart_candles = [{"t": int(c["time"]), "open": c["open"], "high": c["high"],
                          "low": c["low"], "close": c["close"]} for c in candles]
        result = {
            "status": "OK",
            "pair": pair,
            "digits": data.get("digits", 5),
            "candle_count": len(chart_candles),
            "candles": chart_candles,
        }
        resp = Response(json.dumps(result, separators=(",", ":")), content_type="application/json")
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    @web_app.route("/api/last-tick")
    def web_api_last_tick():
        """Returns only the latest tick for a pair (very lightweight, for real-time updates)."""
        pair = flask_request.args.get("pair", "").strip()
        if not pair:
            return Response(json.dumps({"status": "ERROR", "error": "Missing pair"}),
                            content_type="application/json", status=400)
        with _web_candle_lock:
            tick = _web_latest_tick.get(pair)
            if tick is None:
                pair_lower = pair.lower()
                for k, v in _web_latest_tick.items():
                    if k.lower() == pair_lower:
                        tick = v
                        break
        if tick is None:
            return Response(json.dumps({"status": "WAIT"}),
                            content_type="application/json", status=200)
        result = {"status": "OK", "pair": pair, **tick}
        resp = Response(json.dumps(result, separators=(",", ":")), content_type="application/json")
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    @web_app.route("/api/health")
    def web_health():
        with _web_candle_lock:
            pair_count = len(_web_candle_store)
        return Response(json.dumps({"status": "OK", "pairs": pair_count,
                                    "uptime": int(time.time() - _web_push_stats["start_time"])}),
                        content_type="application/json")

    import logging as _logging
    _logging.getLogger("werkzeug").setLevel(_logging.ERROR)
    return web_app


def _start_web_server():
    """Start the Flask web server in a daemon thread."""
    if not HAS_FLASK:
        print(f"\n{Colors.DIM}[WebServer] Flask not installed -- no dashboard."
              f"  pip install flask{Colors.RESET}")
        return
    web_app = _build_web_flask_app()
    if web_app is None:
        return

    def _run():
        try:
            web_app.run(host=WEB_SERVER_HOST, port=WEB_SERVER_PORT,
                        debug=False, use_reloader=False, threaded=True)
        except OSError as e:
            if "Address already in use" in str(e) or "10048" in str(e):
                logmsg(f"[WebServer] Port {WEB_SERVER_PORT} already in use -- skipping dashboard")
            else:
                logmsg(f"[WebServer] Failed to start: {e}")
        except Exception as e:
            logmsg(f"[WebServer] Error: {e}")

    t = threading.Thread(target=_run, name="WebDashboard", daemon=True)
    t.start()
    time.sleep(0.6)
    print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}")
    print(f"{Colors.GREEN}  [WebServer] Dashboard running at:{Colors.RESET}")
    print(f"{Colors.BOLD}  http://{WEB_SERVER_HOST}:{WEB_SERVER_PORT}/{Colors.RESET}")
    print(f"{Colors.DIM}  Click any pair card to view its live chart{Colors.RESET}")
    print(f"{Colors.GREEN}{'='*60}{Colors.RESET}\n")


if __name__ == "__main__":
    # ════════════════════════════════════════════════════════════════════
    # STAGE 1: Select Pairs — choose specific pairs or all pairs
    # ════════════════════════════════════════════════════════════════════
    _ALL_PAIRS = list(ASSET_LIST)  # full default list
    _PAIR_COLS = 3
    print()
    print(f"{Colors.BOLD}  Select Pairs to Stream{Colors.RESET}")
    print(f"  {Colors.DIM}{'═' * 68}{Colors.RESET}")
    _col_w = 22
    for _pi in range(0, len(_ALL_PAIRS), _PAIR_COLS):
        _row_parts = []
        for _pj in range(_PAIR_COLS):
            _pidx = _pi + _pj
            if _pidx < len(_ALL_PAIRS):
                _sym = _ALL_PAIRS[_pidx]
                _label = _sym.replace("_otc", "(OTC)").upper()
                _row_parts.append(f"{Colors.CYAN}{_pidx+1:>3}{Colors.RESET}. {_label:<{_col_w}}")
        print("  " + "  ".join(_row_parts))
    print(f"  {Colors.DIM}{'═' * 68}{Colors.RESET}")
    print(f"  {Colors.DIM}Options:{Colors.RESET}")
    print(f"  {Colors.CYAN}[Enter]{Colors.RESET}         -> Stream ALL {len(_ALL_PAIRS)} pairs")
    print(f"  {Colors.CYAN}1,5,12{Colors.RESET}          -> Stream by number (comma-separated)")
    print(f"  {Colors.CYAN}EURUSD,GBPUSD{Colors.RESET}   -> Stream by name (partial match OK)")
    print(f"  {Colors.DIM}{'═' * 68}{Colors.RESET}")
    while True:
        try:
            _pair_input = input(f"{Colors.CYAN}  Your choice: {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            _pair_input = ""
        if not _pair_input:
            ASSET_LIST = list(_ALL_PAIRS)
            print(f"{Colors.GREEN}  -> Streaming ALL {len(ASSET_LIST)} pairs{Colors.RESET}\n")
            break
        _selected = []
        _tokens = [t.strip() for t in _pair_input.replace(';', ',').split(',') if t.strip()]
        _numeric_mode = all(t.isdigit() for t in _tokens)
        if _numeric_mode:
            for _t in _tokens:
                _idx = int(_t) - 1
                if 0 <= _idx < len(_ALL_PAIRS):
                    if _ALL_PAIRS[_idx] not in _selected:
                        _selected.append(_ALL_PAIRS[_idx])
                else:
                    print(f"{Colors.RED}  Invalid number: {_t} (valid: 1-{len(_ALL_PAIRS)}){Colors.RESET}")
        else:
            for _token in _tokens:
                _token_search = _token.upper().replace("-OTC","").replace("_OTC","")
                _matches = [p for p in _ALL_PAIRS if
                            _token_search in p.upper() or
                            p.lower().startswith(_token.lower())]
                if _matches:
                    for _m in _matches:
                        if _m not in _selected:
                            _selected.append(_m)
                else:
                    print(f"{Colors.RED}  No pair found matching: {_token}{Colors.RESET}")
        if _selected:
            ASSET_LIST = _selected
            print(f"{Colors.GREEN}  -> Selected {len(ASSET_LIST)} pair(s):{Colors.RESET}")
            for _s in ASSET_LIST:
                print(f"    {Colors.CYAN}.{Colors.RESET} {_s.replace('_otc','').upper()} (OTC)")
            print()
            break
        else:
            print(f"{Colors.RED}  No valid pairs selected. Try again.{Colors.RESET}")

    # ════════════════════════════════════════════════════════════════════
    # STAGE 2: Select Timeframe — 3 أعمدة × 5 صفوف (بدون خطوط زرقاء كثيرة)
    # ════════════════════════════════════════════════════════════════════
    # ترتيب الفريمات حسب الطلب:
    # العمود الأول (1-5): M1, M2, M3, M5, M10
    # العمود الثاني (6-10): M15, M30, H1, H4, D1
    # العمود الثالث (11-14): S5, S10, S15, S30
    _TF_DISPLAY_ORDER = [
        # (idx, mt4_period, seconds, short_label, full_label)
        (1,  1,    60,    "M1",  "1 minute"),
        (2,  2,    120,   "M2",  "2 minutes"),
        (3,  3,    180,   "M3",  "3 minutes"),
        (4,  5,    300,   "M5",  "5 minutes"),
        (5,  10,   600,   "M10", "10 minutes"),
        (6,  15,   900,   "M15", "15 minutes"),
        (7,  30,   1800,  "M30", "30 minutes"),
        (8,  60,   3600,  "H1",  "1 hour"),
        (9,  240,  14400, "H4",  "4 hours"),
        (10, 1440, 86400, "D1",  "1 day"),
        (11, 1,    5,     "S5",  "5 seconds"),
        (12, 1,    10,    "S10", "10 seconds"),
        (13, 1,    15,    "S15", "15 seconds"),
        (14, 1,    30,    "S30", "30 seconds"),
    ]
    # خريطة (idx → is_subsecond)
    _TF_SUBSEC = {11: True, 12: True, 13: True, 14: True}

    print()
    print(f"{Colors.BOLD}  Select Timeframe{Colors.RESET}")
    print(f"  {Colors.DIM}{'═' * 55}{Colors.RESET}")
    # عرض القائمة في 3 أعمدة × 5 صفوف
    # صف 0: idx 1,6,11 | صف 1: 2,7,12 | صف 2: 3,8,13 | صف 3: 4,9,14 | صف 4: 5,10,—
    _ROWS = [
        (1, 6, 11),   # M1   M15   S5
        (2, 7, 12),   # M2   M30   S10
        (3, 8, 13),   # M3   H1    S15
        (4, 9, 14),   # M5   H4    S30
        (5, 10, None),# M10  D1    —
    ]
    _tf_lookup = {row[0]: row for row in _TF_DISPLAY_ORDER}
    # ثوابت المحاذاة: كل عمود 17 حرف ظاهر، فجوة 2 حرف بين الأعمدة
    # → كل صف = 2 (indent) + 17*3 + 2*2 = 57 حرف (مطابق لخط ═ 55 + 2 indent)
    # الصيغة: "XX - XXXXX - XXX" = 2 + 3 + 5 + 3 + 4 = 17 حرف ظاهر لكل خلية
    _TF_COL_WIDTH = 17
    _TF_GAP = "  "  # فجوة صغيرة بين الأعمدة (قرّب الأعمدة من بعضها)
    for row in _ROWS:
        cells = []
        for idx in row:
            if idx is None:
                # ملء بمسافات بنفس عرض العمود (يحافظ على تساوي طول الصف)
                cells.append(" " * _TF_COL_WIDTH)
                continue
            entry = _tf_lookup[idx]
            sec = entry[2]      # seconds (int)
            label = entry[3]    # short_label (M1, S30, ...)
            # التنسيق: idx(يمين 2) + " - " + sec(يسار 5) + " - " + label(يسار 4) = 17 حرف
            # Cyan = لون الشعار (بدل Yellow)
            cells.append(f"{Colors.CYAN}{idx:>2}{Colors.RESET} - {sec:<5} - {label:<4}")
        print(f"  {cells[0]}{_TF_GAP}{cells[1]}{_TF_GAP}{cells[2]}")
    print(f"  {Colors.DIM}{'═' * 55}{Colors.RESET}")
    while True:
        try:
            tf_choice = input(f"{Colors.CYAN}  Choose 1-14 (default=1 for M1): {Colors.RESET}").strip()
            if not tf_choice:
                _chosen_idx = 1
            else:
                _chosen_idx = int(tf_choice)
                if not (1 <= _chosen_idx <= 14):
                    print(f"{Colors.RED}  Invalid choice (1-14).{Colors.RESET}")
                    continue
            break
        except (ValueError, KeyboardInterrupt):
            print(f"{Colors.RED}  Invalid input.{Colors.RESET}")
        except EOFError:
            _chosen_idx = 1
            break
    _tf_entry = _tf_lookup[_chosen_idx]
    PERIOD, PERIOD_SECONDS = _tf_entry[1], _tf_entry[2]
    _tf_short = _tf_entry[2]
    _tf_full = _tf_entry[3]
    _is_subsecond = _TF_SUBSEC.get(_chosen_idx, False)
    globals()['PERIOD'] = PERIOD
    globals()['PERIOD_SECONDS'] = PERIOD_SECONDS
    if PERIOD_SECONDS < 60:
        globals()['IS_SUBSECOND'] = True
        globals()['SUBSECOND_SECONDS'] = PERIOD_SECONDS
        _subsec_label = f"{PERIOD_SECONDS}S"
        globals()['SUBSECOND_LABEL'] = _subsec_label
        print(f"{Colors.GREEN}  Using timeframe: {_tf_short} - {_tf_full}{Colors.RESET}")
        print(f"{Colors.DIM}  Sub-minute: fetches period=1 history + aggregates locally{Colors.RESET}\n")
    else:
        globals()['IS_SUBSECOND'] = False
        globals()['SUBSECOND_SECONDS'] = 0
        globals()['SUBSECOND_LABEL'] = ""
        print(f"{Colors.GREEN}  Using timeframe: {_tf_short} - {_tf_full}{Colors.RESET}\n")

    # ════════════════════════════════════════════════════════════════════
    # STAGE 3: Select History Size
    # للفريمات الفرعية (subsecond) نستخدم قيمة ثابتة ولا نسأل المستخدم
    # لأن النظام يجلب period=1 ويُجمّع محلياً — عدد الأيام غير ذي معنى هنا
    # ════════════════════════════════════════════════════════════════════
    if PERIOD_SECONDS < 60:
        # الفريمات الفرعية (5S/10S/15S/30S): قيمة ثابتة بدون سؤال
        INITIAL_CANDLES = SUBSECOND_HISTORY_CANDLES
        HISTORY_DAYS = (INITIAL_CANDLES * PERIOD_SECONDS) / 86400.0 * 1.15
        FETCH_DURATION_SECONDS = int(86400 * HISTORY_DAYS)
        globals()['INITIAL_CANDLES'] = INITIAL_CANDLES
        globals()['HISTORY_DAYS'] = HISTORY_DAYS
        globals()['FETCH_DURATION_SECONDS'] = FETCH_DURATION_SECONDS
        # رسالة قصيرة بدل قائمة كاملة
        print(f"{Colors.DIM}  Sub-second timeframe: auto history ({INITIAL_CANDLES} candles, {HISTORY_DAYS:.2f} days){Colors.RESET}\n")
    else:
        # الفريمات 60s+: نسأل المستخدم عن عدد الأيام
        _default_days = (1000 * PERIOD_SECONDS) / 86400.0 * 1.15  # +15% margin
        print(f"{Colors.BOLD}  Select History Size{Colors.RESET}")
        print(f"  {Colors.DIM}Default: 1000 candles ({_default_days:.2f} days). Or enter days manually.{Colors.RESET}")
        while True:
            try:
                days_input = input(f"{Colors.CYAN}  Days (default={_default_days:.2f}): {Colors.RESET}").strip()
                if not days_input:
                    INITIAL_CANDLES = 1000
                    HISTORY_DAYS = _default_days
                else:
                    days_val = float(days_input)
                    if days_val <= 0:
                        print(f"{Colors.RED}  Must be positive.{Colors.RESET}")
                        continue
                    HISTORY_DAYS = days_val * 1.15
                    INITIAL_CANDLES = max(int((days_val * 86400) / PERIOD_SECONDS), 100)
                FETCH_DURATION_SECONDS = int(86400 * HISTORY_DAYS)
                globals()['INITIAL_CANDLES'] = INITIAL_CANDLES
                globals()['HISTORY_DAYS'] = HISTORY_DAYS
                globals()['FETCH_DURATION_SECONDS'] = FETCH_DURATION_SECONDS
                break
            except (ValueError, KeyboardInterrupt):
                print(f"{Colors.RED}  Invalid input.{Colors.RESET}")
            except EOFError:
                INITIAL_CANDLES = 1000
                HISTORY_DAYS = _default_days
                FETCH_DURATION_SECONDS = int(86400 * HISTORY_DAYS)
                globals()['INITIAL_CANDLES'] = INITIAL_CANDLES
                globals()['HISTORY_DAYS'] = HISTORY_DAYS
                globals()['FETCH_DURATION_SECONDS'] = FETCH_DURATION_SECONDS
                break
        print(f"{Colors.GREEN}  Using history: {HISTORY_DAYS:.2f} days = {INITIAL_CANDLES} candles{Colors.RESET}\n")

    # (تم حذف كتلة Dashboard بناءً على طلب المستخدم — الترحيب + القوائم كافية)

    # ════════════════════════════════════════════════════════════════════
    # STAGE 4: Select Domain — عنوان + قائمة مختصرة + سطر إدخال
    # ════════════════════════════════════════════════════════════════════
    saved_host = session_manager.get_saved_host()
    print()
    print(f"{Colors.BOLD}  Select Domain{Colors.RESET}")
    for i, (host, label) in enumerate(DOMAINS, 1):
        marker = f" {Colors.GREEN}(saved){Colors.RESET}" if host == saved_host else ""
        print(f"  {Colors.CYAN}{i}{Colors.RESET} - {label}{marker}")
    _saved_idx = next((i for i, (h, l) in enumerate(DOMAINS) if h == saved_host), 0)
    _default_choice = str(_saved_idx + 1)
    while True:
        try:
            choice = input(f"{Colors.CYAN}  Choose 1-{len(DOMAINS)} (default={_default_choice}): {Colors.RESET}").strip()
            if not choice:
                QX_HOST = saved_host if saved_host else DOMAINS[0][0]
            else:
                idx = int(choice) - 1
                if 0 <= idx < len(DOMAINS):
                    QX_HOST = DOMAINS[idx][0]
                else:
                    print(f"{Colors.RED}  Invalid choice.{Colors.RESET}")
                    continue
            break
        except (ValueError, KeyboardInterrupt):
            print(f"{Colors.RED}  Invalid input.{Colors.RESET}")
        except EOFError:
            QX_HOST = saved_host if saved_host else DOMAINS[0][0]
            break
    globals()['QX_HOST'] = QX_HOST
    print(f"{Colors.GREEN}  Using domain: {QX_HOST}{Colors.RESET}\n")

    # ════════════════════════════════════════════════════════════════════
    # STAGE 5: تسجيل دخول Quotex
    # ════════════════════════════════════════════════════════════════════
    should_force = session_manager.should_force_fresh()
    saved_email = session_manager.get_saved_email()
    success = False
    if saved_email and not should_force:
        print(f"{Colors.GREEN}Found saved email: {saved_email}{Colors.RESET}")
        PASSWORD_INPUT = input(f"{Colors.CYAN} Password: {Colors.RESET}").strip()
        fut = asyncio.run_coroutine_threadsafe(connect_quotex(saved_email, PASSWORD_INPUT, force_fresh=False, max_attempts=3), ASYNC_LOOP)
        success = fut.result(timeout=180)
    if not success:
        print()
        EMAIL_INPUT = input(f"{Colors.CYAN}Email: {Colors.RESET}").strip()
        PASSWORD_INPUT = input(f"{Colors.CYAN}Password: {Colors.RESET}").strip()
        fut = asyncio.run_coroutine_threadsafe(connect_quotex(EMAIL_INPUT, PASSWORD_INPUT, force_fresh=True, max_attempts=3), ASYNC_LOOP)
        success = fut.result(timeout=300)
    if not success:
        print(f"\n{Colors.RED}[FAILED] Could not connect after all attempts.{Colors.RESET}")
        sys.exit(1)
        
    # (FIX D) "Connected successfully!" —
    if WINAPI_AVAILABLE:
        time.sleep(1)
        find_mt4_window()

    # (FIX D) HST —
    try:
        os.makedirs(MT4_HISTORY_PATH, exist_ok=True)
    except Exception:
        pass

    total_assets = len(ASSET_LIST)

    # === Start embedded web dashboard ===
    _start_web_server()

    # ===== FIX 8: 1 — =====
    print(f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  SECTION 1: CANDLE FETCHING ({total_assets} assets, {INITIAL_CANDLES} candles each){Colors.RESET}")
    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}\n")

    all_assets = []
    total_loaded = 0
    consecutive_disconnects = 0
    # v8.3: track consecutive zero-candle assets in subsecond mode.
    # If the server is throttling us, candle counts drop to 0 for several
    # assets in a row. Rather than burning 8 * 30s = 240s in reconnect
    # attempts at the top of the loop, break cleanly after 3 zero-candle
    # assets in a row.
    _subsecond_zero_streak = 0
    for idx, symbol in enumerate(ASSET_LIST, 1):
        # ===== FIX 3: =====
        # auto_reconnect .
        # ASYNC_LOOP run_coroutine_threadsafe
        # main async.
        if not CONNECTION_ALIVE or CLIENT is None or CLIENT.api is None:
            logmsg(f"[fetch_loop] connection dead before asset {idx}/{total_assets}; waiting for reconnect...")
            async def _wait_reconnect(timeout=30.0):
                try:
                    await wait_until(
                        lambda: CONNECTION_ALIVE and CLIENT is not None and CLIENT.api is not None,
                        timeout=timeout,
                        poll_interval=0.5,
                    )
                    return True
                except asyncio.TimeoutError:
                    return False
            reconnected = asyncio.run_coroutine_threadsafe(_wait_reconnect(30.0), ASYNC_LOOP).result(timeout=35)
            if reconnected:
                consecutive_disconnects = 0
            else:
                consecutive_disconnects += 1
                logmsg(f"[fetch_loop] reconnect failed within 30s (streak={consecutive_disconnects})")
                if consecutive_disconnects >= MAX_RECONNECTS_DURING_FETCH:
                    logmsg(f"[fetch_loop] giving up after {consecutive_disconnects} failed reconnects")
                    break
                continue
        asset = Asset(symbol)
        display = pretty_asset_name(symbol)
        all_assets.append(asset)
        ALL_STREAMING_ASSETS.append(asset)
        start_time = time.time()
        # v8.3/v8.11: Use SUBSECOND_ASSET_DELAY (2.0s) for subsecond mode,
        # M1_ASSET_DELAY (1.0s) for M1 bridge mode, 0.1s (FETCH_ASSET_DELAY)
        # for other 60s+ timeframes (normal speed).
        if IS_SUBSECOND:
            _asset_delay = SUBSECOND_ASSET_DELAY
        elif PERIOD_SECONDS == 60 and M1_USE_1S_BRIDGE:
            _asset_delay = M1_ASSET_DELAY  # v8.11: 1.0s between assets in M1 bridge mode
        else:
            _asset_delay = FETCH_ASSET_DELAY
        # v8.1: dispatch to the correct stream function based on IS_SUBSECOND.
        _stream_fn = subsecond_stream if IS_SUBSECOND else realtime_stream
        # Start stream FIRST (before historical fetch). For subsecond mode,
        # subsecond_stream() will schedule fetch_subsecond_history in the
        # background. For normal mode, realtime_stream() just collects ticks.
        #
        # v8.9: start realtime_stream in ALL modes, including TEST MODE.
        # In TEST MODE, realtime_stream will use stream_period=1 (see Patch 2
        # in realtime_stream's body) -- it subscribes to 1s ticks (NOT 1m
        # snapshots), so no 199-candle pollution. update_candle buckets the
        # 1s ticks into 1m candles, updating the last candle for live price.
        asset.stream_task = asyncio.run_coroutine_threadsafe(_stream_fn(asset), ASYNC_LOOP)
        # Small delay to let stream subscribe before fetch
        time.sleep(0.1)
        # v8.1: In subsecond mode, subsecond_stream() already triggers the
        # background history fetch via fetch_subsecond_history(asset). Calling
        # fetch_candles_with_retry on top of that would conflict. So we skip
        # the normal historical fetch path here.
        if IS_SUBSECOND:
            # v8.2: DO NOT call fetch_subsecond_history explicitly here --
            # subsecond_stream() already scheduled it as a background task.
            # Poll asset.candles length and the asset._bg_tasks set, exit as
            # soon as the background fetch completes (success or failure) OR
            # the target candle count is reached. Hard cap = 15s.
            _subsecond_wait_deadline = time.time() + 15.0  # v8.3: was 45s -- reduced to lower WebSocket pressure
            while time.time() < _subsecond_wait_deadline:
                # If the background task set is empty, the fetch has finished
                _bg_tasks = getattr(asset, '_bg_tasks', None)
                if _bg_tasks is not None and len(_bg_tasks) == 0:
                    break
                # If we already have enough candles, no need to wait further
                if len(getattr(asset, 'candles', [])) >= SUBSECOND_HISTORY_CANDLES:
                    break
                # Bail out early if the connection died
                if not CONNECTION_ALIVE:
                    break
                time.sleep(0.5)
            candles_count = len(getattr(asset, 'candles', []))
            elapsed = time.time() - start_time
            if candles_count >= MIN_CANDLES_THRESHOLD:
                total_loaded += candles_count
                consecutive_disconnects = 0
                # v8.3: reset the zero-candle streak -- we got data, server is healthy
                _subsecond_zero_streak = 0
                _warn = "" if candles_count >= SUBSECOND_HISTORY_CANDLES else f" {Colors.YELLOW}(target {SUBSECOND_HISTORY_CANDLES}){Colors.RESET}"
                print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.GREEN}{candles_count} {SUBSECOND_LABEL} candles in {elapsed:.1f}s{Colors.RESET}{_warn} Streaming")
                # Push to web dashboard immediately after successful fetch
                try:
                    _web_update_asset(asset, full_resync=True)
                except Exception:
                    pass
            else:
                print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.RED}Only {candles_count} {SUBSECOND_LABEL} candles{Colors.RESET} Streaming")
                try:
                    _web_update_asset(asset, full_resync=True)
                except Exception:
                    pass
                # v8.3: increment zero-candle streak. If the server has throttled us
                # into oblivion (3 zero-candle assets in a row), break the loop cleanly
                if candles_count == 0:
                    _subsecond_zero_streak += 1
                    logmsg(
                        f"[fetch_loop] zero-candle streak: {_subsecond_zero_streak}/"
                        f"{SUBSECOND_MAX_ZERO_STREAK} (WebSocket likely throttled)"
                    )
                    if _subsecond_zero_streak >= SUBSECOND_MAX_ZERO_STREAK:
                        logmsg(
                            f"[fetch_loop] giving up after {_subsecond_zero_streak} "
                            f"consecutive zero-candle assets (server throttled)"
                        )
                        break
                else:
                    # Got some candles (just below threshold) -- reset streak
                    _subsecond_zero_streak = 0
        else:
            # Normal mode (60s+ timeframes): fetch historical candles in parallel
            # while realtime_stream collects live ticks.
            #
            # v8.4/v8.6: For M1 (PERIOD_SECONDS == 60) and when M1_USE_1S_BRIDGE is True,
            # run the new advanced flow:
            #   a) fetch 1s candles + aggregate to 1m  -> bridge_1m_candles
            #      (1s is the most granular -- 60 consecutive 1s = 1 perfect 1m candle,
            #      NO gaps as long as the 1s data is continuous)
            #   b) fetch 1000 historical 1m candles (disabling the old bridge fetch
            #      for this asset -- we have a better 1s->1m bridge already)
            #   c) merge: [historical] + [bridge (where ts > last historical ts)]
            #   d) write HST + update MT4_WRITER.sync_state
            #   e) print summary: "N historical + M bridge (from K 1s) = total"
            _is_m1_with_1s_bridge = (PERIOD_SECONDS == 60 and M1_USE_1S_BRIDGE)
            bridge_1m_candles = []
            if _is_m1_with_1s_bridge:
                # Step (a): fetch 1s -> aggregate to 1m.
                # v8.5/v8.6: fetch_1s_and_aggregate_to_1m returns (candles_1m, n_1s).
                # It also prints its own console line showing the 1s fetch result
                # (the user explicitly asked "must print the loading of those candles
                # before loading 1-minute candles"). This print fires BEFORE the
                # historical 1m fetch begins.
                _n_1s_fetched = 0
                try:
                    # v8.4 fix: this is in the main SYNC thread -- no 'await'.
                    # asyncio.run_coroutine_threadsafe(...).result(timeout=N) bridges sync->async.
                    bridge_1m_candles, _n_1s_fetched = asyncio.run_coroutine_threadsafe(
                        fetch_1s_and_aggregate_to_1m(asset, idx=idx, total=total_assets),
                        ASYNC_LOOP,
                    ).result(timeout=M1_BRIDGE_TIMEOUT + 5)
                except Exception as e:
                    logmsg(f"[fetch_loop:{display}] 1s->1m bridge failed (non-fatal): {e}")
                    bridge_1m_candles = []
                    _n_1s_fetched = 0
                logmsg(
                    f"[fetch_loop:{display}] 1s->1m bridge: {_n_1s_fetched} 1s -> {len(bridge_1m_candles)} 1m ready"
                )
                # v8.7: TEST MODE -- if M1_TEST_1S_ONLY is True, skip the 1000
                # historical 1m fetch entirely and use ONLY the 1s->1m aggregated
                # candles. This lets us verify the aggregation produces valid 1m
                # candles that MT4 can render.
                if M1_TEST_1S_ONLY:
                    # Use ONLY the 1s->1m aggregated candles as the base for asset.candles.
                    asset.candles = list(bridge_1m_candles) if bridge_1m_candles else []
                    # Replace any sync_state that realtime_stream might have auto-created
                    if asset.symbol in MT4_WRITER.sync_state:
                        del MT4_WRITER.sync_state[asset.symbol]
                    if asset.candles:
                        asset.price = asset.candles[-1]['close']
                    asset.write(force=True)
                    MT4_WRITER.sync_state[asset.symbol] = {
                        'period': PERIOD,
                        'candles': list(asset.candles),
                        'last_write': 0,
                        'last_price': float(asset.candles[-1]['close']) if asset.candles else 0.0,
                    }
                    candles_count = len(asset.candles)
                    elapsed = time.time() - start_time
                    # Print with a clear TEST MODE indicator so the user knows
                    # they're in the verification flow.
                    if candles_count > 0:
                        total_loaded += candles_count
                        consecutive_disconnects = 0
                        print(
                            f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} "
                            f"{Colors.YELLOW}TEST MODE{Colors.RESET} {Colors.GREEN}{candles_count} 1m candles "
                            f"(from {_n_1s_fetched} 1s) in {elapsed:.1f}s{Colors.RESET} Streaming"
                        )
                    else:
                        print(
                            f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} "
                            f"{Colors.RED}TEST MODE: 0 1m candles (1s fetch failed){Colors.RESET}"
                        )
                    # Push to web dashboard
                    try:
                        _web_update_asset(asset, full_resync=True)
                    except Exception:
                        pass
                else:
                    # v8.11: intra-asset delay between the 1s fetch and the 1000
                    # historical fetch. User explicitly asked: "مهلة ثم يجلب
                    # 1000 شمعة" (a delay then fetch 1000 candles).
                    time.sleep(M1_INTRA_ASSET_DELAY)
                    # Normal flow (M1_TEST_1S_ONLY = False): fetch 1000 historical
                    # 1m candles + merge with the 1s->1m bridge.
                    # Step (b): fetch 1000 historical 1m candles. Temporarily disable
                    # the old _bridge_fetch_recent_candles for this asset -- we already
                    # have a more granular 1s->1m bridge that we'll merge in step (c).
                    _saved_bridge_flag = BRIDGE_FETCH_ENABLED
                    globals()['BRIDGE_FETCH_ENABLED'] = False
                    try:
                        fut = asyncio.run_coroutine_threadsafe(fetch_candles_with_retry(asset, max_retries=MAX_FETCH_RETRIES, idx=idx, total=total_assets), ASYNC_LOOP)
                        candles_count, attempts = fut.result(timeout=180)
                    finally:
                        globals()['BRIDGE_FETCH_ENABLED'] = _saved_bridge_flag
                    # Step (c): merge historical + bridge.
                    # v8.12: REPLACE matching historical candles with bridge candles
                    # (not just APPEND new ones). User explicitly asked:
                    #   "شموع 6 او 8 شموع الاولى من الشموع التاريخية يجب ان
                    #    يتم استبدالها ب شموع 1 ثانية التي جمعناها لكي نتخلص
                    #    من الثغرات"
                    #   (The first 6-8 historical candles should be REPLACED by the
                    #    1s-aggregated candles to eliminate gaps.)
                    #
                    # Logic (same as _bridge_fetch_recent_candles):
                    #   1. Walk the historical candles.
                    #   2. For each historical candle whose timestamp matches a
                    #      bridge candle, REPLACE it with the bridge candle
                    #      (more accurate, NO GAPS -- built from 60 raw 1s candles).
                    #   3. APPEND any remaining bridge candles (those whose
                    #      timestamps are newer than the last historical).
                    #   4. Sort + dedup by time.
                    if bridge_1m_candles and asset.candles:
                        # v8.13: cap the bridge to the NEWEST M1_BRIDGE_REPLACE_COUNT
                        # candles (default 6). The server returns a variable count
                        # (8/12/13), but we only need the last 6 to cover the max
                        # 5-candle gap. Using more would just replace historical
                        # candles unnecessarily; using fewer might leave a gap.
                        bridge_for_merge = bridge_1m_candles[-M1_BRIDGE_REPLACE_COUNT:]
                        bridge_by_time = {c['time']: c for c in bridge_for_merge}
                        merged_list = []
                        _replaced_count = 0
                        for c in asset.candles:
                            if c['time'] in bridge_by_time:
                                # REPLACE: bridge candle is more accurate (no gaps)
                                merged_list.append(bridge_by_time.pop(c['time']))
                                _replaced_count += 1
                            else:
                                merged_list.append(c)
                        # APPEND remaining bridge candles (newer than last historical)
                        _appended_count = len(bridge_by_time)
                        merged_list.extend(bridge_by_time.values())
                        # Sort + dedup by time
                        seen = set()
                        deduped = []
                        for c in sorted(merged_list, key=lambda x: x['time']):
                            if c['time'] not in seen:
                                seen.add(c['time'])
                                deduped.append(c)
                        asset.candles = deduped
                        # Step (d): write merged HST + update sync_state
                        if asset.candles:
                            asset.price = asset.candles[-1]['close']
                        asset.write(force=True)
                        MT4_WRITER.sync_state[asset.symbol] = {
                            'period': PERIOD,
                            'candles': list(asset.candles),
                            'last_write': 0,
                            'last_price': float(asset.candles[-1]['close']) if asset.candles else 0.0,
                        }
                        candles_count = len(asset.candles)
                        logmsg(
                            f"[fetch_loop:{display}] merged: REPLACED {_replaced_count} historical "
                            f"+ APPENDED {_appended_count} new bridge = {candles_count} total "
                            f"(used {len(bridge_for_merge)} of {len(bridge_1m_candles)} bridge candles, "
                            f"source: {_n_1s_fetched} 1s)"
                        )
                    # Step (e): print summary -- v8.5/v8.6: include the 1s source count
                    # v8.13: show the actual capped count used for replacement,
                    # plus the full bridge count from the server, plus the 1s source.
                    elapsed = time.time() - start_time
                    if candles_count >= MIN_CANDLES_THRESHOLD:
                        total_loaded += candles_count
                        consecutive_disconnects = 0
                        if bridge_1m_candles and _n_1s_fetched > 0:
                            _full_bridge = len(bridge_1m_candles)
                            _used_bridge = min(_full_bridge, M1_BRIDGE_REPLACE_COUNT)
                            if _full_bridge > _used_bridge:
                                _bridge_str = f" + {_used_bridge} bridge (capped from {_full_bridge}, from {_n_1s_fetched} 1s)"
                            else:
                                _bridge_str = f" + {_used_bridge} bridge (from {_n_1s_fetched} 1s)"
                        elif bridge_1m_candles:
                            _bridge_str = f" + {len(bridge_1m_candles)} bridge"
                        else:
                            _bridge_str = ""
                        print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.GREEN}{candles_count} candles{_bridge_str} in {elapsed:.1f}s{Colors.RESET} Streaming")
                        # Push to web dashboard
                        try:
                            _web_update_asset(asset, full_resync=True)
                        except Exception:
                            pass
                    else:
                        print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.RED}Only {candles_count} candles{Colors.RESET} Streaming")
                        try:
                            _web_update_asset(asset, full_resync=True)
                        except Exception:
                            pass
            else:
                # Non-M1 60s+ timeframes: keep the original behavior
                fut = asyncio.run_coroutine_threadsafe(fetch_candles_with_retry(asset, max_retries=MAX_FETCH_RETRIES, idx=idx, total=total_assets), ASYNC_LOOP)
                try:
                    candles_count, attempts = fut.result(timeout=180)
                    elapsed = time.time() - start_time
                    if candles_count >= MIN_CANDLES_THRESHOLD:
                        total_loaded += candles_count
                        consecutive_disconnects = 0
                        attempts_str = "" if attempts == 1 else f" ({attempts} attempts)"
                        print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.GREEN}{candles_count} candles in {elapsed:.1f}s{attempts_str}{Colors.RESET} Streaming")
                        # Push to web dashboard immediately after successful fetch
                        try:
                            _web_update_asset(asset, full_resync=True)
                        except Exception:
                            pass
                    else:
                        print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.RED}Only {candles_count} candles{Colors.RESET} Streaming")
                        try:
                            _web_update_asset(asset, full_resync=True)
                        except Exception:
                            pass
                except Exception as e:
                    print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.RED}Error: {str(e)[:30]}{Colors.RESET}")
                    if "Connection" in str(e) or "closed" in str(e).lower():
                        consecutive_disconnects += 1
                        if consecutive_disconnects >= MAX_RECONNECTS_DURING_FETCH:
                            logmsg(f"[fetch_loop] too many disconnects ({consecutive_disconnects}); aborting fetch")
                            break
        # Merge: any live ticks collected during fetch are already in asset.candles
        # fetch_candles_with_retry overwrites asset.candles with historical only.
        # To preserve live ticks, merge them back after fetch.
        # (handled inside realtime_stream which appends to asset.candles)
        # ===== FIX 7: cooldown — =====
        # . keepalive_loop .
        if FETCH_COOLDOWN_EVERY > 0 and idx > 0 and idx % FETCH_COOLDOWN_EVERY == 0 and idx < total_assets:
            logmsg(f"[fetch_loop] cooldown {FETCH_COOLDOWN_DURATION}s after {idx}/{total_assets} assets")
            time.sleep(FETCH_COOLDOWN_DURATION)
        else:
            # Use 1.0s for sub-minute (server sensitive to period=1), 0.1s for 60s+
            time.sleep(_asset_delay)

    # NOTE: gap filler runs automatically on its interval (every GAP_FILL_REFRESH_INTERVAL).
    # First cycle waits 60s, then runs periodically. Not forced at startup.
    # Gap fill respects the user's chosen timeframe via dynamic _align_time/_fill_missing_slots.

    asyncio.run_coroutine_threadsafe(health_monitor(), ASYNC_LOOP)
    asyncio.run_coroutine_threadsafe(auto_reconnect(), ASYNC_LOOP)
    asyncio.run_coroutine_threadsafe(keepalive_loop(), ASYNC_LOOP)
    asyncio.run_coroutine_threadsafe(stale_message_watchdog(), ASYNC_LOOP)
    # v9.0: DISABLED background refetchers per user request:
    #   - mt4_gap_filler(): re-filled candle gaps every GAP_FILL_REFRESH_INTERVAL (300s).
    #     The user wants the bridge/gap-filling to happen DURING the initial fetch only
    #     (already handled by the M1_USE_1S_BRIDGE flow), not after.
    #   - web_candle_refresher(): re-pushed full candle history to the web dashboard
    #     every WEB_PUSH_INTERVAL (30s). The user wants the chart to use only live ticks
    #     after the initial load (faster, less server load).
    # Live updates are now driven by realtime_stream -> _web_update_asset() per tick.
    # asyncio.run_coroutine_threadsafe(mt4_gap_filler(), ASYNC_LOOP)
    # asyncio.run_coroutine_threadsafe(web_candle_refresher(), ASYNC_LOOP)
    
    # ===== FIX 8: dashboard — 3 =====
    # 1: ( )
    # 2: ( status line )
    # 3: ( mt4_gap_filler)
    print(f"\n{Colors.GREEN}{'═'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  All assets loaded and streaming!{Colors.RESET}")
    print(f"  Total: {total_loaded} candles for {len(all_assets)} assets")
    print(f"  History window: {HISTORY_DAYS} day (optimized, fast fetch)")
    print(f"  HST Files: {'ENABLED (every %ss)' % WRITE_INTERVAL if WRITE_HST_FILES_ENABLED else 'DISABLED — web dashboard only'}")
    print(f"  Refresh: BATCHED (every {REFRESH_INTERVAL}s)")
    print(f"  Stream Poll: {STREAM_POLL_INTERVAL}s  (v9.0: max-speed live ticks)")
    print(f"  Health Monitor: ACTIVE (Lenient: ignores websocket flickers)")
    print(f"  Keepalive Ping: ACTIVE (every {KEEPALIVE_PING_INTERVAL}s, multi-type)")
    print(f"  Stale Watchdog: ACTIVE (recycles if silent > {STALE_MESSAGE_TIMEOUT}s)")
    print(f"  Auto-Reconnect: instant detect + exponential backoff (never gives up)")
    print(f"  Internal Watchdog: ACTIVE (recycles stale connections > 90s)")
    print(f"  Fetch: {FETCH_MAX_WORKERS} workers, {FETCH_CHUNK_SIZE}c/batch, {FETCH_BATCH_DELAY}s delay, {FETCH_ASSET_DELAY}s between assets")
    print(f"  Retry: {MAX_FETCH_RETRIES} attempts, backoff {RETRY_BACKOFF_BASE}-{RETRY_BACKOFF_MAX}s")
    print(f"  {Colors.CYAN}Web Updates: LIVE per-tick (no background refetch){Colors.RESET}")
    if PERIOD_SECONDS == 60 and M1_USE_1S_BRIDGE:
        print(f"  {Colors.CYAN}M1 Bridge: 1s->1m active during initial fetch{Colors.RESET}")
    print(f"{Colors.GREEN}{'═'*60}{Colors.RESET}\n")

    # ===== FIX E/F/G: — =====
    # FIX E: ( 6)
    # FIX F: ( print() )
    # FIX G: ( / ) +
    # FIX H: (columns/rows) —

    import shutil as _shutil
    def _get_term_size():
        try:
            s = _shutil.get_terminal_size((80, 24))
            return s.columns, s.lines
        except Exception:
            return 80, 24

    def _fmt_price(p):
        if p <= 0: return "—"
        if p >= 1000: return f"{p:.3f}"
        if p >= 100:  return f"{p:.3f}"
        if p >= 1:    return f"{p:.5f}"
        return f"{p:.5f}"

    def _draw_live_table(first_draw=False):
        cols, rows = _get_term_size()
        # ===== FIX H: — =====
        # : 25 chars (name=12 + price=10 + )
        # : 50 chars (name=25 + price=15 + status=8 + )
        cols = max(25, cols)
        if cols >= 55:
            name_w, price_w = 25, 15
            show_status = True
        elif cols >= 40:
            name_w, price_w = 20, 12
            show_status = True
        elif cols >= 30:
            name_w, price_w = 15, 10
            show_status = False
        else:
            name_w, price_w = 12, 8
            show_status = False
        bar_w = max(20, min(70, cols - 2))
        # ( )
        header_lines = 3
        data_lines = len(all_assets) + 1  # +1
        gap_lines = 0
        if GAP_FILL_SUMMARY:
            gap_lines = 3  # ===, summary, ===
        # status messages lines (queued log messages)
        msg_lines_count = min(len(_STATUS_MESSAGES_QUEUE), 3)
        msg_lines = msg_lines_count + (1 if msg_lines_count > 0 else 0)  # +1 for separator
        total_lines = header_lines + data_lines + gap_lines + msg_lines
        if not first_draw:
            sys.stdout.write(f"\033[{total_lines}A")
        # ===== =====
        sys.stdout.write(f"\033[2K{Colors.CYAN}{'═'*bar_w}{Colors.RESET}\n")
        sys.stdout.write(f"\033[2K{Colors.BOLD}  LIVE PRICES{Colors.RESET}\n")
        sys.stdout.write(f"\033[2K{Colors.CYAN}{'═'*bar_w}{Colors.RESET}\n")
        # ===== =====
        for asset in all_assets:
            display = pretty_asset_name(asset.api_symbol)
            # name_w
            if len(display) > name_w:
                display = display[:name_w-1] + "~"
            # FIX G:
            name_visible = f"{display:<{name_w}}"
            name_colored = f"{Colors.BLUE}{name_visible}{Colors.RESET}"
            # FIX G: ( / )
            price_str = _fmt_price(asset.price)
            if asset.previous_price > 0 and asset.price > 0:
                if asset.price > asset.previous_price:
                    price_colored = f"{Colors.GREEN}{price_str:<{price_w}}{Colors.RESET}"
                elif asset.price < asset.previous_price:
                    price_colored = f"{Colors.RED}{price_str:<{price_w}}{Colors.RESET}"
                else:
                    price_colored = f"{price_str:<{price_w}}"
            else:
                price_colored = f"{price_str:<{price_w}}"

            if show_status:
                if asset.updates > 0:
                    status_str = f"{Colors.GREEN}LIVE{Colors.RESET}"
                else:
                    status_str = f"{Colors.RED}WAIT{Colors.RESET}"
                sys.stdout.write(f"\033[2K  {name_colored} {price_colored} {status_str}\n")
            else:
                sys.stdout.write(f"\033[2K  {name_colored} {price_colored}\n")

        if CONNECTION_ALIVE:
            conn_status = f"{Colors.GREEN}CONNECTED{Colors.RESET}"
        else:
            conn_status = f"{Colors.RED}RECONNECTING...{Colors.RESET}"
        if show_status:
            sys.stdout.write(f"\033[2K  {Colors.BLUE}{'Connection':<{name_w}}{Colors.RESET} {'':<{price_w}} {conn_status}\n")
        else:
            sys.stdout.write(f"\033[2K  {Colors.BLUE}{'Connection':<{name_w}}{Colors.RESET} {conn_status}\n")
        # ===== FIX F: ( ) =====
        if GAP_FILL_SUMMARY:
            summary = GAP_FILL_SUMMARY
            # bar_w-4
            max_len = bar_w - 4
            if len(summary) > max_len:
                summary = summary[:max_len-3] + "..."
            # color by content:
            if "ABORTED" in GAP_FILL_SUMMARY or ("Failed:" in GAP_FILL_SUMMARY and "0 failed" not in GAP_FILL_SUMMARY):
                summary_colored = f"{Colors.RED}{summary}{Colors.RESET}"
            elif "COMPLETE" in GAP_FILL_SUMMARY or ("pushed" in GAP_FILL_SUMMARY and "ABORTED" not in GAP_FILL_SUMMARY):
                summary_colored = f"{Colors.GREEN}{summary}{Colors.RESET}"
            elif "refreshing" in GAP_FILL_SUMMARY or GAP_FILL_ACTIVE:
                summary_colored = f"{Colors.CYAN}{summary}{Colors.RESET}"
            else:
                summary_colored = summary
            sys.stdout.write(f"\033[2K{Colors.CYAN}{'═'*bar_w}{Colors.RESET}\n")
            sys.stdout.write(f"\033[2K  {summary_colored}\n")
            sys.stdout.write(f"\033[2K{Colors.CYAN}{'═'*bar_w}{Colors.RESET}\n")
        # Display queued log messages (last 3)
        if _STATUS_MESSAGES_QUEUE:
            sys.stdout.write(f"\033[2K{Colors.DIM}{'─'*bar_w}{Colors.RESET}\n")
            for msg in _STATUS_MESSAGES_QUEUE[-3:]:
                # truncate to bar_w-4
                if len(msg) > bar_w - 4:
                    msg = msg[:bar_w-7] + "..."
                sys.stdout.write(f"\033[2K  {Colors.DIM}{msg}{Colors.RESET}\n")
        sys.stdout.flush()

    # Initial draw
    _draw_live_table(first_draw=True)
    print()
    print(f"{Colors.CYAN}Live streaming active. Press Enter for menu, Ctrl+C to stop.{Colors.RESET}")
    print()

    # Interactive menu state
    stop_requested = False
    reinit_requested = False
    _enter_pressed = threading.Event()

    def _stdin_listener():
        while not stop_requested and not reinit_requested:
            try:
                line = sys.stdin.readline()
                if line == '' or line is None:
                    time.sleep(0.5)
                    continue
                _enter_pressed.set()
                while _enter_pressed.is_set() and not stop_requested and not reinit_requested:
                    time.sleep(0.1)
            except (KeyboardInterrupt, EOFError):
                time.sleep(0.5)
            except Exception:
                time.sleep(0.5)

    _stdin_thread = threading.Thread(target=_stdin_listener, daemon=True, name="StdinListener")
    _stdin_thread.start()

    def _show_interactive_menu():
        print()
        print(f"{Colors.CYAN}{'═'*70}{Colors.RESET}")
        print(f"{Colors.BOLD}  MENU{Colors.RESET}")
        print(f"{Colors.CYAN}{'═'*70}{Colors.RESET}")
        print(f"  {Colors.CYAN}1{Colors.RESET} - Change Timeframe (current: {_current_period_label()})")
        print(f"  {Colors.CYAN}2{Colors.RESET} - Change History days (current: {HISTORY_DAYS:.2f}d = {INITIAL_CANDLES} candles)")
        print(f"  {Colors.CYAN}3{Colors.RESET} - Change both timeframe and history days")
        print(f"  {Colors.CYAN}4{Colors.RESET} - Resume streaming (continue)")
        print(f"  {Colors.CYAN}5{Colors.RESET} - Exit program")
        print(f"{Colors.CYAN}{'═'*70}{Colors.RESET}")
        while True:
            try:
                c = input(f"{Colors.CYAN}Choose 1-5: {Colors.RESET}").strip()
                if c in ('1', '2', '3', '4', '5'):
                    return int(c)
                print(f"{Colors.RED}Invalid choice.{Colors.RESET}")
            except (ValueError, KeyboardInterrupt):
                print(f"{Colors.RED}Invalid input.{Colors.RESET}")
            except EOFError:
                return 4

    def _choose_timeframe():
        # نفس تنسيق القائمة الأولية: 3 أعمدة × 5 صفوف (مع علامة Current)
        print()
        print(f"{Colors.BOLD}  Select Timeframe{Colors.RESET}")
        print(f"  {Colors.DIM}{'═' * 55}{Colors.RESET}")
        _ROWS_LOCAL = [
            (1, 6, 11), (2, 7, 12), (3, 8, 13), (4, 9, 14), (5, 10, None),
        ]
        _TF_COL_WIDTH = 17
        _TF_GAP = "  "
        for row in _ROWS_LOCAL:
            cells = []
            for idx in row:
                if idx is None:
                    cells.append(" " * _TF_COL_WIDTH)
                    continue
                tf_tuple = TIMEFRAMES[idx - 1]
                mt4_p = tf_tuple[0]
                secs = tf_tuple[1]
                label = tf_tuple[2]
                is_current = (mt4_p == PERIOD and secs == PERIOD_SECONDS)
                # إضافة علامة (*) إذا كان الفريم الحالي
                marker = "*" if is_current else " "
                # التنسيق: "XX*SSSSS-LABEL" (17 حرف ظاهر) — علامة * بديل (current)
                cells.append(f"{Colors.CYAN}{idx:>2}{marker}{Colors.RESET}{secs:<5}- {label:<4}")
            print(f"  {cells[0]}{_TF_GAP}{cells[1]}{_TF_GAP}{cells[2]}")
        print(f"  {Colors.DIM}{'═' * 55}{Colors.RESET}")
        print(f"  {Colors.DIM}(* = current){Colors.RESET}")
        while True:
            try:
                tf_choice = input(f"{Colors.CYAN}  Choose 1-14 (default=1 for M1): {Colors.RESET}").strip()
                if not tf_choice:
                    return TIMEFRAMES[0]
                tf_idx = int(tf_choice) - 1
                if 0 <= tf_idx < len(TIMEFRAMES):
                    return TIMEFRAMES[tf_idx]
                print(f"{Colors.RED}  Invalid choice (1-14).{Colors.RESET}")
            except (ValueError, KeyboardInterrupt):
                print(f"{Colors.RED}  Invalid input.{Colors.RESET}")
            except EOFError:
                return TIMEFRAMES[0]

    def _choose_history_days():
        # للفريمات الفرعية: لا نسأل، نُرجع قيمة ثابتة (نفس سلوك Initial Setup)
        if PERIOD_SECONDS < 60:
            _auto_days = (SUBSECOND_HISTORY_CANDLES * PERIOD_SECONDS) / 86400.0 * 1.15
            print(f"{Colors.DIM}  Sub-second timeframe: auto history ({SUBSECOND_HISTORY_CANDLES} candles){Colors.RESET}")
            return _auto_days, SUBSECOND_HISTORY_CANDLES
        # للفريمات 60s+: نسأل المستخدم
        print(f"{Colors.CYAN}{'═'*70}{Colors.RESET}")
        print(f"{Colors.BOLD}  Select History Size:{Colors.RESET}")
        print(f"{Colors.CYAN}{'═'*70}{Colors.RESET}")
        _default_days_local = (1000 * PERIOD_SECONDS) / 86400.0 * 1.15  # +15% margin
        print(f"  {Colors.CYAN}Enter number of days (e.g., 1, 2, 3, 4...)")
        print(f"   Or press Enter for default 1000 candles ({_default_days_local:.2f} days){Colors.RESET}")
        print(f"{Colors.CYAN}{'═'*70}{Colors.RESET}")
        while True:
            try:
                days_input = input(f"{Colors.CYAN}Days: {Colors.RESET}").strip()
                if not days_input:
                    return _default_days_local, 1000
                days_val = float(days_input)
                if days_val <= 0:
                    print(f"{Colors.RED}Must be positive.{Colors.RESET}")
                    continue
                # Apply 15% margin to user-specified days too
                days_with_margin = days_val * 1.15
                candles = max(int((days_val * 86400) / PERIOD_SECONDS), 100)
                return days_with_margin, candles
            except (ValueError, KeyboardInterrupt):
                print(f"{Colors.RED}Invalid input.{Colors.RESET}")
            except EOFError:
                return _default_days_local, 1000

    # status update loop with interactive menu support
    while not stop_requested:
        try:
            while True:
                if _enter_pressed.is_set() or stop_requested or reinit_requested:
                    break
                _draw_live_table(first_draw=False)
                time.sleep(STATUS_REFRESH_INTERVAL)
            if stop_requested:
                break
            if reinit_requested:
                break
            action = _show_interactive_menu()
            _enter_pressed.clear()
            if action == 4:
                _draw_live_table(first_draw=True)
                continue
            elif action == 5:
                stop_requested = True
                break
            elif action in (1, 2, 3):
                new_period = PERIOD
                new_period_seconds = PERIOD_SECONDS
                if action in (1, 3):
                    _new_tf = _choose_timeframe()
                    new_period = _new_tf[0]
                    new_period_seconds = _new_tf[1]
                    # set subsecond globals for the restart (based on period_seconds, not flag)
                    if new_period_seconds < 60:
                        globals()['IS_SUBSECOND'] = True
                        globals()['SUBSECOND_SECONDS'] = new_period_seconds
                        globals()['SUBSECOND_LABEL'] = f"{new_period_seconds}S"
                    else:
                        globals()['IS_SUBSECOND'] = False
                        globals()['SUBSECOND_SECONDS'] = 0
                        globals()['SUBSECOND_LABEL'] = ""
                new_days = HISTORY_DAYS
                new_candles = INITIAL_CANDLES
                # للفريمات الفرعية: _choose_history_days يُرجع قيمة ثابتة تلقائياً
                # للفريمات 60s+: يسأل المستخدم
                if action in (2, 3):
                    new_days, new_candles = _choose_history_days()
                globals()['PERIOD'] = new_period
                globals()['PERIOD_SECONDS'] = new_period_seconds
                globals()['HISTORY_DAYS'] = new_days
                globals()['INITIAL_CANDLES'] = new_candles
                globals()['FETCH_DURATION_SECONDS'] = int(86400 * new_days) if new_days > 0 else 0
                print(f"{Colors.GREEN}Reinitializing with {_current_period_label()}, {new_days:.2f} days = {new_candles} candles...{Colors.RESET}")
                reinit_requested = True
                break
        except KeyboardInterrupt:
            stop_requested = True
            break
        except Exception as e:
            log_exception("main status loop", e)
            try:
                print(f"\n{Colors.CYAN}[main loop] recovered from error: {e}{Colors.RESET}", flush=True)
            except Exception:
                pass
            time.sleep(1)

    # If reinit was requested: نُعيد تشغيل البرنامج بشكل نظيف
    # ملاحظة: هذا إعادة بناء كاملة (full re-init) لكنها أسرع من إغلاق الترمنال
    # لأن البرنامج يبدأ مباشرة من نقطة الترخيص المحفوظ (لا يسأل المستخدم ثانية)
    if reinit_requested:
        print(f"\n{Colors.CYAN}Applying new timeframe settings...{Colors.RESET}")
        sys.stdout.flush()
        time.sleep(1.0)
        # إعادة تنفيذ البرنامج بشكل نظيف
        os.execv(sys.executable, [sys.executable] + sys.argv)

    # graceful shutdown
    cols, rows = _get_term_size()
    gap_lines = 3 if GAP_FILL_SUMMARY else 0
    total_lines_now = 3 + len(all_assets) + 1 + gap_lines
    sys.stdout.write(f"\033[{total_lines_now}B\n")
    sys.stdout.flush()
    print(f"{Colors.RED}Stopped{Colors.RESET}")
    print(f"{Colors.CYAN}Total updates: {sum(a.updates for a in all_assets):,}{Colors.RESET}")
    print(f"{Colors.CYAN}Total candles stored: {sum(len(a.candles) for a in all_assets):,}{Colors.RESET}")
    print()
    writer_thread.running = False
