#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quotex Mega Fetcher — Full-Featured Candle + Profit + Live Price Engine
=======================================================================
A complete port of the working `wedsoket_.py` engine, but focused on what
the user actually needs for the competition:

  1. EXACTLY 500 candles per asset for all 13 OTC pairs (M1 default).
  2. PROFIT/PAYOUT percentage fetched from instruments/list (binary frame).
  3. GAP-FILLING via _fill_missing_slots (verbatim port).
  4. LIVE PRICE via subscribe_realtime_candle + depth/follow + quotes/stream.
  5. NEVER-SLEEP engine: keepalive_loop + stale_message_watchdog + auto_reconnect
     + health_monitor running concurrently in background.

ARCHITECTURE
------------
  - Reuses the Quotex client from OTC_canda_.py for connection / auth / WS.
  - Installs interceptors on WebsocketClient.on_message to capture:
      (a) binary instruments/list frames (JSON, 0x04-prefixed)
      (b) live tick arrays (quotes/stream, depth/change)
      (c) historical candle responses (history/load, history/list/v2)
  - Runs four background asyncio tasks:
      (i)   keepalive_loop: ping every 5s
      (ii)  stale_message_watchdog: detect silent connection (45s)
      (iii) auto_reconnect: rebuild connection on loss (exponential backoff)
      (iv)  health_monitor: periodic state check (20s)
  - Fetch logic uses overlapping chunks (60 candles, 10 overlap) + dedup +
    gap-fill + truncate/pad to exactly 500.

USAGE
-----
    python3 mega_fetch.py

After login, the script:
  1. Fetches the instruments list (to get profit % per asset).
  2. Subscribes to live price for all 13 OTC pairs.
  3. Fetches exactly 500 candles per asset (gap-filled).
  4. Saves results to candles_otc_data/{asset}_1m_500c_{8-hex}.json

OUTPUT
------
    candles_otc_data/{asset}_{tf}m_500c_{8-hex}.json
"""

# ============================================================================
# SECTION 0: STANDARD LIBRARY IMPORTS
# ============================================================================
import os
import sys
import ssl
import json
import time
import random
import re
import shutil
import logging
import asyncio
import threading
import traceback
import itertools
import contextlib
import platform
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict, OrderedDict, deque
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field

# Third-party dependencies (required by the Quotex connection engine)
import certifi
import requests
import websocket
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

try:
    import orjson as _orjson
    HAS_ORJSON = True
except ImportError:
    _orjson = None
    HAS_ORJSON = False

# ============================================================================

# ============================================================================
# SECTION 1: QUOTEX CONNECTION ENGINE (embedded — no external file needed)
# ============================================================================
# This section contains the FULL Quotex connection engine, ported verbatim
# from OTC_canda_.py. It includes:
#   - SSL setup + logging
#   - Event-driven wait primitives
#   - HTTP Navigator (CipherSuiteAdapter, Browser)
#   - HTTP Login & Settings
#   - WebSocket Client & State
#   - Quotex API Core (QuotexAPI class)
#   - Candle parsing helpers
#   - Quotex stable API class (with get_historical_candles)
#   - Helper utilities (logmsg, Colors, credentials, save_candles_to_json)
#   - keepalive_loop + auto_reconnect_loop + connect_quotex
#
# By embedding this code directly, mega_fetch.py is now a SINGLE-FILE solution
# that does NOT require OTC_canda_.py to be present in the same folder.

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
# SECTION 1.5: EVENT-DRIVEN WAIT PRIMITIVES
# ==============================================================================
async def wait_until(predicate: Callable[[], bool], *, timeout: float = 10.0,
                      poll_interval: float = 0.05) -> None:
    """يستدعي predicate() كل poll_interval ثانية حتى يُعيد True أو ينتهي timeout."""
    async def _loop():
        while not predicate():
            await asyncio.sleep(poll_interval)
    await asyncio.wait_for(_loop(), timeout=timeout)


async def wait_for_first_event(*events: asyncio.Event, timeout: float = 10.0) -> int:
    """ينتظر أول event يُطلق من القائمة ويعيد indexه. يطلق TimeoutError عند المهلة."""
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
        raise asyncio.TimeoutError()
    except asyncio.CancelledError:
        for t in tasks:
            if not t.done():
                t.cancel()
        raise


def _schedule_event_set(event: Optional[asyncio.Event],
                        loop: Optional[asyncio.AbstractEventLoop]) -> None:
    if event is None or loop is None:
        return
    try:
        if not loop.is_closed() and loop.is_running():
            loop.call_soon_threadsafe(event.set)
    except RuntimeError:
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
        try:
            user_agent = UserAgent().random
        except Exception:
            user_agent = USER_AGENT
    output_file = Path(resource_path("session.json"))
    with session_lock:
        all_sessions = {}
        if output_file.exists():
            try:
                all_sessions = json.loads(output_file.read_text())
            except json.JSONDecodeError:
                pass
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
            try:
                current_sessions = json.loads(output_file.read_text())
            except json.JSONDecodeError:
                pass
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
    __attrs__ = ['ssl_context', 'max_retries', 'config', '_pool_connections',
                 '_pool_maxsize', '_pool_block', 'source_address']

    def __init__(self, *args, **kwargs):
        self.ssl_context = kwargs.pop('ssl_context', None)
        self.cipherSuite = kwargs.pop('cipherSuite',
            'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
            'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
            'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
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
        self.cipherSuite = kwargs.pop('cipherSuite',
            'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
            'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
            'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        # استخرج proxies قبل super().__init__ (الذي يعيد ضبط self.proxies إلى {})
        _proxies = kwargs.pop('proxies', None)
        super().__init__(*args, **kwargs)
        # اضبط proxies بعد super().__init__ حتى لا تُكتب فوقها بـ {}
        # هذا يحل المشكلة: send_request يفحص self.proxies لكن Session.__init__ يفرغها
        self.proxies = _proxies
        self.headers.update(self.get_headers())
        self.mount('https://', CipherSuiteAdapter(
            ecdhCurve=self.ecdhCurve, cipherSuite=self.cipherSuite,
            server_hostname=self.server_hostname, source_address=self.source_address,
            ssl_context=ssl_context, max_retries=retry_strategy))

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
        if self.response and not self.response.ok:
            raise RuntimeError(self.response.reason)
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
    base_url = 'quotex.com'  # <--- تم التحديث هنا
    https_base_url = f'https://{base_url}'

    def __init__(self, api, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api = api
        self.headers = self.get_headers()
        self.full_url = f"{self.https_base_url}/{api.lang}"

    def get_token(self):
        self.headers["Connection"] = "keep-alive"
        self.headers["Accept-Encoding"] = "gzip, deflate, br"
        self.headers["Accept-Language"] = "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3"
        self.headers["Accept"] = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                                  "image/avif,image/webp,*/*;q=0.8")
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
            input_message = (f'{auth_body.find("p").text}: '
                             if auth_body.find("p")
                             else "Enter the PIN code sent to your email: ")
            await self.awaiting_pin(data, input_message)
            await asyncio.sleep(1)
            return self.success_login()
        return self.success_login()

    def success_login(self):
        if "trade" in str(self.response.url):
            return True, "Login successful."
        soup = self.get_soup()
        not_available = soup.select_one("#tab-1 > div > div.modal-sign__not-avalible__title")
        if not_available:
            return False, f"Service unavailable: {not_available.get_text(strip=True)}"
        error = soup.select_one("#tab-1 form > div:nth-child(2) > div")
        msg = error.get_text(strip=True) if error else "Unknown error"
        return False, f"Login failed. {msg}"

    async def __call__(self, username, password, user_data_dir=None):
        data = {"_token": self.get_token(), "email": username,
                "password": password, "remember": 1}
        status, msg = await self._post(data)
        if status:
            self.get_profile()
        return status, msg


class Settings(Browser):
    def __init__(self, api):
        # مرّر proxies من api إلى Settings
        proxies_dict = api._normalize_proxies(api.proxies) if hasattr(api, '_normalize_proxies') else None
        super().__init__(proxies=proxies_dict)
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
# SECTION 5: WEBSOCKET CLIENT & STATE
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
        # EVENT-DRIVEN: تُهيّأ lazily من async context
        self.ws_connected_event: Optional[asyncio.Event] = None
        self.ws_closed_event: Optional[asyncio.Event] = None
        self.auth_accepted_event: Optional[asyncio.Event] = None
        self.auth_rejected_event: Optional[asyncio.Event] = None
        self.ws_error_event: Optional[asyncio.Event] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def init_events(self) -> None:
        if self.ws_connected_event is None: self.ws_connected_event = asyncio.Event()
        if self.ws_closed_event is None: self.ws_closed_event = asyncio.Event()
        if self.auth_accepted_event is None: self.auth_accepted_event = asyncio.Event()
        if self.auth_rejected_event is None: self.auth_rejected_event = asyncio.Event()
        if self.ws_error_event is None: self.ws_error_event = asyncio.Event()
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None

    def reset_events(self) -> None:
        for ev in (self.ws_connected_event, self.ws_closed_event,
                   self.auth_accepted_event, self.auth_rejected_event,
                   self.ws_error_event):
            if ev is not None:
                ev.clear()

    def signal_ws_connected(self): _schedule_event_set(self.ws_connected_event, self._loop)
    def signal_ws_closed(self): _schedule_event_set(self.ws_closed_event, self._loop)
    def signal_auth_accepted(self): _schedule_event_set(self.auth_accepted_event, self._loop)
    def signal_auth_rejected(self): _schedule_event_set(self.auth_rejected_event, self._loop)
    def signal_ws_error(self): _schedule_event_set(self.ws_error_event, self._loop)


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
        try:
            if self.api is not None:
                self.api.last_message_at = time.time()
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
                self.state.signal_auth_rejected()
            elif "s_authorization" in msg_str:
                self.state.check_accepted_connection = True
                self.state.check_rejected_connection = False
                self.state.auth_status = AuthStatus.AUTHENTICATED
                self.state.status = WebsocketStatus.CONNECTED
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
                    self.api.candles.candles_data = (message.get("candles")
                                                    or message.get("data")
                                                    or message.get("history"))
                    asyncio.run_coroutine_threadsafe(
                        self.api.event_registry.set_event(f'candles_ready_{asset}', message),
                        loop)
                    index = message.get("index")
                    if index is not None:
                        asyncio.run_coroutine_threadsafe(
                            self.api.event_registry.set_event(f'candles_ready_{asset}_{index}', message),
                            loop)
            if isinstance(message, dict) and (message.get("liveBalance") or message.get("demoBalance")):
                self.api.account_balance = message
        except Exception as e:
            logger.debug(f"Error processing message: {e}")

    def on_error(self, wss, error):
        logger.error(error)
        self.state.websocket_error_reason = str(error)
        self.state.check_websocket_if_error = True
        self.state.status = WebsocketStatus.ERROR
        self.state.check_accepted_connection = False
        self.state.signal_ws_error()

    def on_open(self, wss):
        logger.info("Websocket client connected.")
        self.state.check_websocket_if_connect = 1
        self.state.status = WebsocketStatus.CONNECTED
        self.state.signal_ws_connected()
        asset_name = self.api.current_asset or "EURUSD_otc"
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
        logger.info("Websocket connection closed.")
        self.state.check_websocket_if_connect = 0
        self.state.status = WebsocketStatus.DISCONNECTED
        self.state.check_accepted_connection = False
        self.state.signal_ws_closed()

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
        # مرّر proxies إلى Browser حتى يستخدمها HTTP (Login + Settings)
        # إذا proxy هو "http://1.2.3.4:8080" نُحوّله إلى dict متوافق مع requests
        proxies_dict = self._normalize_proxies(proxies)
        self.browser = Browser(proxies=proxies_dict)
        self.browser.set_headers()
        self.settings = Settings(self)
        self.settings.proxies = proxies_dict  # تأكد أن Settings أيضاً يستخدم البروكسي
        self.candles = CandlesObj()
        self.candle_v2_data = {}
        self.realtime_price = defaultdict(list)
        self.event_registry = EventRegistry()
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None
        self.last_message_at: float = time.time()

    @staticmethod
    def _normalize_proxies(proxies) -> Optional[dict]:
        """يحوّل proxy string (أو dict) إلى dict صيغة requests."""
        if not proxies:
            return None
        if isinstance(proxies, dict):
            return proxies
        if isinstance(proxies, str):
            # صيغة مثل "http://1.2.3.4:8080" أو "socks5://1.2.3.4:1080"
            return {"http": proxies, "https": proxies}
        return None

    @property
    def login(self):
        # مرّر proxies إلى Login حتى يستخدمها طلبات HTTP لتسجيل الدخول
        return Login(self, proxies=self._normalize_proxies(self.proxies))

    def send_websocket_request(self, data, no_force_send=True):
        if no_force_send:
            deadline = time.time() + 5.0
            while (self.state.ssl_Mutual_exclusion or self.state.ssl_Mutual_exclusion_write):
                if time.time() > deadline:
                    break
                time.sleep(0.001)
        self.state.ssl_Mutual_exclusion_write = True
        try:
            if self.websocket_client and self.websocket_client.wss:
                self.websocket_client.wss.send(data)
        finally:
            self.state.ssl_Mutual_exclusion_write = False

    def subscribe_realtime_candle(self, asset, period):
        self.realtime_price[asset] = []
        data = f'42["instruments/update", {json.dumps({"asset": asset, "period": period})}]'
        return self.send_websocket_request(data)

    def follow_candle(self, asset):
        return self.send_websocket_request(f'42["depth/follow", {json.dumps(asset)}]')

    def chart_notification(self, asset):
        return self.send_websocket_request(
            f'42["chart_notification/get", {json.dumps({"asset": asset, "version": "1.0.0"})}]')

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
        self.state.init_events()
        self.state.reset_events()
        try:
            self.state._loop = asyncio.get_running_loop()
        except RuntimeError:
            self.state._loop = None

        if not self.state.SSID:
            await self.authenticate()
        self.websocket_client = WebsocketClient(self)
        payload = {
            "suppress_origin": True, "ping_interval": 24, "ping_timeout": 20,
            "ping_payload": "2",
            "origin": self.https_url, "host": f"ws2.{self.host}",
            "sslopt": {"check_hostname": True, "cert_reqs": ssl.CERT_REQUIRED,
                       "ca_certs": cacert, "context": ssl_context},
        }
        # مرّر البروكسي إلى WebSocket إذا وُجد
        proxy_dict = self._normalize_proxies(self.proxies)
        if proxy_dict:
            proxy_url = proxy_dict.get("http") or proxy_dict.get("https")
            if proxy_url:
                # تحليل "http://host:port" أو "socks5://host:port"
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(proxy_url)
                    if parsed.hostname and parsed.port:
                        payload["http_proxy_host"] = parsed.hostname
                        payload["http_proxy_port"] = parsed.port
                        if parsed.scheme.startswith("socks"):
                            payload["http_proxy_auth_timeout"] = 30
                except Exception:
                    pass
        if platform.system() == "Linux":
            payload["sslopt"]["ssl_version"] = ssl.PROTOCOL_TLS
        self.websocket_thread = threading.Thread(
            target=self.websocket_client.wss.run_forever, kwargs=payload)
        self.websocket_thread.daemon = True
        self.websocket_thread.start()

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
        if not self.state.SSID:
            return False
        if self.state.auth_accepted_event is None:
            self.state.init_events()
        self.state.auth_accepted_event.clear()
        self.state.auth_rejected_event.clear()

        payload = {"session": self.state.SSID, "isDemo": self.account_type, "tournamentId": 0}
        data = f'42["authorization",{json.dumps(payload)}]'
        self.send_websocket_request(data)

        try:
            idx = await wait_for_first_event(
                self.state.auth_accepted_event,
                self.state.auth_rejected_event,
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return False
        return idx == 0

    async def connect(self, is_demo):
        self.account_type = 1 if is_demo else 0
        self.state.ssl_Mutual_exclusion = False
        self.state.ssl_Mutual_exclusion_write = False
        check_websocket, websocket_reason = await self.start_websocket()
        if not check_websocket:
            return check_websocket, websocket_reason
        check_ssid = await self.send_ssid()
        if not check_ssid:
            await self.authenticate()
            if self.state.SSID:
                await self.send_ssid()
        return check_websocket, websocket_reason

    async def close(self):
        if self.websocket_client and self.websocket_client.wss:
            self.websocket_client.wss.close()
            await asyncio.sleep(1)
        if self.websocket_thread and self.websocket_thread.is_alive():
            self.websocket_thread.join(timeout=5)
        return True


# ==============================================================================
# SECTION 7: QUOTEX STABLE API + CANDLE PARSING
# ==============================================================================
_request_counter = itertools.count(int(time.time() * 1000))


def _parse_raw_candles(raw_candles):
    """يُحوّل الشموع الخام من WebSocket إلى قائمة dicts بصيغة OHLC موحّدة.

    يدعم ثلاث صيغ يمكن أن يُرسلها الخادم عبر "history/load":
      1) [time, open, close, high, low]       — صيغة Quotex الشائعة (5 عناصر)
      2) [time, open, close, high, low, vol] — نفس الصيغة مع volume (6 عناصر)
      3) {"time", "open", "high", "low", "close", ...} — dict
      4) [time, price(, volume)] — tick فردي (يُحوّل إلى شمعة بسيطة)
    """
    if not raw_candles:
        return []
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
                    parsed.append({'time': t, 'open': o, 'high': h, 'low': l,
                                   'close': cl, 'volume': v})
            elif isinstance(c, (list, tuple)) and len(c) >= 5:
                t = int(c[0]); o = float(c[1]); cl = float(c[2])
                h = float(c[3]); l = float(c[4])
                v = int(c[5]) if len(c) >= 6 else 0
                if t > 0 and o > 0 and h > 0 and l > 0 and cl > 0:
                    parsed.append({'time': t, 'open': o, 'high': h, 'low': l,
                                   'close': cl, 'volume': v})
            elif isinstance(c, (list, tuple)) and len(c) >= 2:
                t = int(c[0]); p = float(c[1])
                v = int(c[2]) if len(c) >= 3 else 0
                if t > 0 and p > 0:
                    parsed.append({'time': t, 'open': p, 'high': p, 'low': p,
                                   'close': p, 'volume': v})
        except (TypeError, ValueError):
            continue
    return parsed


def process_candles_v2(history, asset, data):
    if not history or not isinstance(history, dict):
        return data if data else []
    candles_data = history.get(asset, {})
    candles = candles_data.get("candles", [])[1:] if candles_data else []
    combined = candles + (data if data else [])
    if combined:
        candle_dict = {c.get('time'): c for c in combined if isinstance(c, dict) and 'time' in c}
        return list(candle_dict.values()) if candle_dict else []
    return combined


def merge_candles(candles_data):
    if not candles_data:
        return []
    candle_dict = {c['time']: c for c in candles_data if isinstance(c, dict) and 'time' in c}
    return sorted(candle_dict.values(), key=lambda x: x['time']) if candle_dict else []


class Quotex:
    def __init__(self, email=None, password=None, host="quotex.com", lang="en",  # <--- تم التحديث هنا
                 proxies=None, user_data_dir="browser",
                 asset_default="EURUSD_otc", period_default=60):
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
        if self.api is None:
            return False
        try:
            await wait_until(
                lambda: self.api.state.check_accepted_connection == 1,
                timeout=2.0, poll_interval=0.05,
            )
            return True
        except asyncio.TimeoutError:
            return self.api.state.check_accepted_connection == 1

    async def connect(self):
        self.api = QuotexAPI(self.host, self.email, self.password, self.lang,
                             proxies=self.proxies, user_data_dir=self.user_data_dir)
        self.api.session_data = self.session_data
        self.api.state.SSID = self.session_data.get("token")
        self.api._async_loop = asyncio.get_running_loop()
        if not self.session_data.get("token"):
            check, reason = await self.api.authenticate()
            if not check:
                return check, reason
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

    async def start_candles_stream(self, asset="EURUSD_otc", period=60):
        if self.api:
            self.api.current_asset = asset
            self.api.current_period = period
            self.api.subscribe_realtime_candle(asset, period)
            self.api.chart_notification(asset)
            self.api.follow_candle(asset)

    async def _fetch_historical_batch(self, asset, fetch_time, offset, period, index, timeout):
        if self.api is None:
            return None
        payload = {"asset": asset, "index": index, "time": fetch_time,
                   "offset": offset, "period": period}
        ws_msg = f'42["history/load",{json.dumps(payload)}]'
        event_name = f'candles_ready_{asset}_{index}'
        await self.api.event_registry.clear_event(event_name)
        self.api.send_websocket_request(ws_msg)
        try:
            return await self.api.event_registry.wait_event(event_name, timeout=timeout)
        except Exception:
            return None

    def _parse_historical_candles(self, raw_data):
        if raw_data is None:
            return []
        raw_candles = raw_data.get("data", []) or raw_data.get("candles", [])
        if not raw_candles:
            return []
        parsed = []
        for c in raw_candles:
            if isinstance(c, list) and len(c) >= 5:
                parsed.append({
                    "time": int(c[0]), "open": float(c[1]),
                    "close": float(c[2]), "high": float(c[3]), "low": float(c[4]),
                })
            elif isinstance(c, dict) and "time" in c:
                parsed.append(c)
        return parsed

    async def get_historical_candles(self, asset, amount_of_seconds, period,
                                     timeout=30, max_workers=5, progress_callback=None):
        """يجلب شموع تاريخية للأصل المطلوب.

        المعاملات:
          asset            : اسم الأصل بصيغة Quotex (مثلاً EURUSD_otc)
          amount_of_seconds: عدد الثواني المطلوب جلبها للماضي
          period           : طول الشمعة بالثواني (60 = M1, 300 = M5, 3600 = H1)
          max_workers      : عدد العمال المتوازين (5 = السرعة الأصلية)
        """
        max_workers = max_workers or 1
        chunk_seconds = period * FETCH_CHUNK_SIZE  # period * 200 = عدد الثواني لكل batch
        all_candles = {}
        current_time = int(time.time())
        target_start_time = current_time - amount_of_seconds
        block_size = amount_of_seconds // max_workers
        semaphore = asyncio.Semaphore(max_workers)

        async def worker(start_t, end_t, worker_id):
            worker_candles = {}
            async with semaphore:
                oldest_t = start_t
                consecutive_failures = 0
                while oldest_t > end_t:
                    # تحقق من الاتصال قبل كل batch
                    if not self.api or not getattr(self.api.state, 'check_accepted_connection', False):
                        break
                    index = next(_request_counter)
                    batch_data = await self._fetch_historical_batch(
                        asset, oldest_t, chunk_seconds, period, index, timeout)
                    if not batch_data:
                        oldest_t -= chunk_seconds
                        consecutive_failures += 1
                        if consecutive_failures >= 3:
                            break
                        await asyncio.sleep(FETCH_BATCH_DELAY * 2)
                        continue
                    consecutive_failures = 0
                    new_batch = self._parse_historical_candles(batch_data)
                    if not new_batch:
                        oldest_t -= chunk_seconds
                        continue
                    batch_times = []
                    for c in new_batch:
                        ts = c['time']
                        if ts >= end_t and ts <= start_t:
                            worker_candles[ts] = c
                            batch_times.append(ts)
                    if not batch_times:
                        oldest_t -= chunk_seconds
                        continue
                    batch_times.sort()
                    new_oldest = batch_times[0]
                    if progress_callback:
                        progress_callback(start_t - new_oldest, start_t - end_t,
                                          len(worker_candles), f"Worker-{worker_id}")
                    oldest_t = new_oldest if new_oldest < oldest_t else oldest_t - chunk_seconds
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
            for c in batch:
                all_candles[c['time']] = c
        return sorted(all_candles.values(), key=lambda x: x['time'])

    async def close(self):
        if self.api:
            return await self.api.close()
        return True


# ==============================================================================
# SECTION 8: CONSTANTS & CONFIG (جديد)
# ==============================================================================
CREDENTIALS_FILE = Path("credentials.json")

# مجلد حفظ الشموع — ملفات JSON تُحفظ مباشرة هنا بدون مجلدات فرعية.
CANDLES_DIR = Path("candles_otc_data")
CANDLES_DIR.mkdir(exist_ok=True)

# قائمة العملات الـ13 (OTC) — تُجلب تلقائياً عند اختيار الخيار 2 بعد تسجيل الدخول.
OTC_ASSETS = [
    "BRLUSD_otc",   # Brazil
    "USDARS_otc",   # Argentina
    "USDBDT_otc",   # Bangladesh
    "USDCOP_otc",   # Colombia
    "USDDZD_otc",   # Algeria
    "USDEGP_otc",   # Egypt
    "USDIDR_otc",   # Indonesia
    "USDINR_otc",   # India
    "USDMXN_otc",   # Mexico
    "USDNGN_otc",   # Nigeria
    "USDPHP_otc",   # Philippines
    "USDPKR_otc",   # Pakistan
    "USDZAR_otc",   # South Africa
]

# إعدادات الجلب — متوازي 5 workers (السرعة الأصلية ~4s لكل 1000 شمعة)
FETCH_MAX_WORKERS = 5
FETCH_CHUNK_SIZE = 200         # 200 شمعة لكل batch
FETCH_BATCH_DELAY = 0.1        # 0.1s بين batches
MAX_FETCH_RETRIES = 5
RETRY_BACKOFF_BASE = 2
RETRY_BACKOFF_MAX = 15
KEEPALIVE_INTERVAL = 5         # ping كل 5 ثوانٍ للحفاظ على الاتصال بين عمليات الجلب
RECONNECT_CHECK_INTERVAL = 10  # فحص حالة الاتصال كل 10 ثوانٍ
MAX_RECONNECT_ATTEMPTS = 5     # عدد محاولات إعادة الاتصال قبل الاستسلام
RECONNECT_BACKOFF_BASE = 3     # ثانية بين المحاولات (يتضاعف)

# أدوات التسجيل
LOG_FILE = Path("candal.log")


def logmsg(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  \033[2m[{ts}]\033[0m {msg}")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def log_exception(context: str, exc: BaseException):
    ts = datetime.now().strftime("%H:%M:%S")
    tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(f"  \033[91m[{ts}] FATAL in {context}: {exc}\033[0m")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] FATAL in {context}: {exc}\n{tb_text}\n")
    except Exception:
        pass


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# التقاط استثناءات الـ threads
def _thread_excepthook(args):
    log_exception(f"thread '{args.thread.name}'", args.exc_value)
threading.excepthook = _thread_excepthook


def _main_excepthook(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    log_exception("main thread (top level)", exc_value)
sys.excepthook = _main_excepthook


# ==============================================================================
# SECTION 9: CREDENTIALS MANAGEMENT (حفظ الإيميل وكلمة المرور)
# ==============================================================================
SESSION_FILE = Path("session.json")
BROWSER_DIR = Path("browser")


def purge_old_session() -> None:
    """Delete any saved Quotex session so we always log in fresh.

    Quotex may reject connections that reuse a stale token from a previous
    run. By deleting session.json and the browser/ cache directory on
    startup, we force a brand-new login every time.
    """
    try:
        if SESSION_FILE.exists():
            SESSION_FILE.unlink()
    except Exception:
        pass
    try:
        if BROWSER_DIR.exists():
            shutil.rmtree(BROWSER_DIR, ignore_errors=True)
    except Exception:
        pass


def load_credentials() -> Optional[Dict[str, str]]:
    """يقرأ بيانات الدخول من credentials.json. يُعيد None إذا لم توجد."""
    if not CREDENTIALS_FILE.exists():
        return None
    try:
        data = json.loads(CREDENTIALS_FILE.read_text())
        if data.get("email") and data.get("password"):
            return data
        return None
    except Exception:
        return None


def save_credentials(email: str, password: str, proxy: str = "") -> bool:
    """يحفظ بيانات الدخول والبروكسي في credentials.json لإعادة الاستخدام لاحقاً."""
    try:
        existing = {}
        if CREDENTIALS_FILE.exists():
            try: existing = json.loads(CREDENTIALS_FILE.read_text())
            except Exception: pass
        existing.update({
            "email": email,
            "password": password,
            "proxy": proxy,
            "saved_at": int(time.time())
        })
        CREDENTIALS_FILE.write_text(json.dumps(existing, indent=2))
        return True
    except Exception as e:
        logmsg(f"Failed to save credentials: {e}")
        return False


# ==============================================================================
# SECTION 10: ASSET NAME NORMALIZATION
# ==============================================================================
def normalize_asset(raw: str) -> str:
    """يُنظّف اسم الأصل ولا يضيف _otc إلا إذا كتبتها أنت.

    أمثلة:
      "XAUUSD"      -> "XAUUSD"        (حقيقي، بدون otc)
      "XAUUSD_otc"  -> "XAUUSD_otc"
      "xauusd otc"  -> "XAUUSD_otc"
      "EUR/USD"     -> "EURUSD"
    """
    s = re.sub(r'[^a-zA-Z0-9]', '', raw.strip())
    if not s:
        return ""
    is_otc = s.upper().endswith("OTC")
    if is_otc:
        s = s[:-3]
    s = s.upper()
    if not s:
        return ""
    return f"{s}_otc" if is_otc else s


def pretty_asset(symbol: str, timeframe_min: int) -> str:
    """يُعيد اسم عرض جميل: EUR/USD · OTC (M5)"""
    base = symbol
    suffix = ""
    if base.upper().endswith("_OTC"):
        base = base[:-4]
        suffix = " · OTC"
    if len(base) == 6 and base.isalpha():
        pretty = f"{base[:3]}/{base[3:]}{suffix}"
    else:
        pretty = f"{base}{suffix}"
    return f"{pretty} (M{timeframe_min})"


# ==============================================================================
# SECTION 11: JSON FILE SAVING (منسّق: شمعة واحدة في كل سطر)
# ==============================================================================
def save_candles_to_json(candles: List[Dict], asset: str, timeframe_min: int, days: int) -> Optional[Path]:
    """يحفظ الشموع في ملف JSON منسّق باسم: {asset}_{timeframe}m_{days}d_{random}.json

    كل شمعة في سطر واحد مع تاريخ مقروء (UTC) بجانب الـ timestamp.
    """
    if not candles:
        logmsg("No candles to save.")
        return None

    def fmt_dt(ts: int) -> str:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    random_suffix = ''.join(random.choices('0123456789abcdef', k=8))
    filepath = CANDLES_DIR / f"{asset}_{timeframe_min}m_{days}d_{random_suffix}.json"

    meta = {
        "asset": asset,
        "display_name": pretty_asset(asset, timeframe_min),
        "is_otc": asset.lower().endswith("_otc"),
        "timeframe_minutes": timeframe_min,
        "days_requested": days,
        "candle_count": len(candles),
        "first_candle": fmt_dt(candles[0]['time']),
        "last_candle": fmt_dt(candles[-1]['time']),
        "first_candle_time": candles[0]['time'],
        "last_candle_time": candles[-1]['time'],
        "timezone": "UTC",
        "fetch_time": datetime.now().isoformat(timespec="seconds"),
        "fetch_timestamp": int(time.time()),
    }

    try:
        meta_txt = json.dumps(meta, indent=2, ensure_ascii=False).replace("\n", "\n  ")
        rows = []
        for c in candles:
            row = {
                "datetime": fmt_dt(c['time']),
                "time": c['time'],
                "open": c['open'],
                "high": c['high'],
                "low": c['low'],
                "close": c['close'],
                "volume": c.get('volume', 0),
            }
            rows.append("    " + json.dumps(row, ensure_ascii=False))
        body = ",\n".join(rows)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('{\n')
            f.write(f'  "metadata": {meta_txt},\n')
            f.write('  "candles": [\n')
            f.write(body + '\n')
            f.write('  ]\n}\n')
        return filepath
    except Exception as e:
        log_exception("save_candles_to_json", e)
        return None


# ==============================================================================
# SECTION 12: FETCH LOGIC (جديد)
# ==============================================================================
async def keepalive_loop(client: Quotex, stop_event: asyncio.Event):
    """حلقة keepalive بسيطة ترسل ping كل KEEPALIVE_INTERVAL ثانية.
    تحافظ على اتصال WebSocket حياً بين عمليات الجلب، وتتوقف فوراً عند ضبط stop_event."""
    while not stop_event.is_set():
        try:
            if client and client.api:
                client.api.send_websocket_request("2", no_force_send=False)
                client.api.send_websocket_request('42["tick"]', no_force_send=False)
        except Exception:
            pass
        # انتظار قابل للإيقاف: يخرج فوراً عند ضبط stop_event
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=KEEPALIVE_INTERVAL)
        except asyncio.TimeoutError:
            pass  # انتهى المحدّد = أرسل ping التالي


# ------------------------------------------------------------------------------
# آلية "عدم النوم" (مستوحاة من الكود الضخم wedsoket_.py)
# ------------------------------------------------------------------------------
# مشترك بين keepalive_loop و auto_reconnect_loop لتجديد كائن Quotex عند الفقد.
# يتم تحديثه عبر attribute set بدلاً من closure لتفادي مشاكل الـ late binding.
class _ClientHolder:
    """حاوية بسيطة تتيح لـ auto_reconnect استبدال كائن Quotex برمجياً."""
    def __init__(self, client: Optional[Quotex]):
        self.client = client
        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.proxies: Optional[str] = None
        self.lock = asyncio.Lock()


def _is_connection_alive(client: Optional[Quotex]) -> bool:
    """فحص سريع: هل اتصال Quotex ما زال نشطاً؟
    يعيد False بأمان لأي كائن لا يحتوي على api أو state."""
    if client is None:
        return False
    try:
        api = getattr(client, "api", None)
        if api is None:
            return False
        state = getattr(api, "state", None)
        if state is None:
            return False
        return bool(getattr(state, "check_accepted_connection", False))
    except Exception:
        return False


async def auto_reconnect_loop(holder: _ClientHolder, stop_event: asyncio.Event,
                              on_reconnect=None) -> None:
    """راقب حالة الاتصال كل RECONNECT_CHECK_INTERVAL ثانية. عند الفقد،
    حاول إعادة الاتصال تلقائياً حتى MAX_RECONNECT_ATTEMPTS محاولة.

    - لا يوقف البرنامج أبداً ما لم يُضبط stop_event.
    - يستبدل holder.client بكائن Quotex جديد عند نجاح إعادة الاتصال.
    - يستدعي on_reconnect(new_client) إن وُجدت (لإعلام الـ fetcher باستخدام الكائن الجديد).
    """
    while not stop_event.is_set():
        try:
            alive = _is_connection_alive(holder.client)
            if not alive:
                logmsg(f"{Colors.YELLOW}[reconnect] connection lost, attempting reconnect...{Colors.RESET}")
                backoff = RECONNECT_BACKOFF_BASE
                for attempt in range(1, MAX_RECONNECT_ATTEMPTS + 1):
                    if stop_event.is_set():
                        return
                    try:
                        new_client = Quotex(
                            email=holder.email,
                            password=holder.password,
                            host="quotex.com",
                            lang="en",
                            proxies=holder.proxies,
                        )
                        check, reason = await new_client.connect()
                        if check:
                            try:
                                await new_client.change_account("PRACTICE")
                                await asyncio.sleep(0.5)
                            except Exception:
                                pass
                            async with holder.lock:
                                # أغلق القديم بهدوء قبل الاستبدال
                                try:
                                    if holder.client:
                                        await holder.client.close()
                                except Exception:
                                    pass
                                holder.client = new_client
                            logmsg(f"{Colors.GREEN}[reconnect] reconnect successful on attempt {attempt}{Colors.RESET}")
                            if on_reconnect:
                                try:
                                    on_reconnect(new_client)
                                except Exception as cb_err:
                                    logmsg(f"[reconnect] on_reconnect callback raised: {cb_err}")
                            break
                        else:
                            err = str(reason) if reason else "Unknown"
                            logmsg(f"[reconnect] attempt {attempt}/{MAX_RECONNECT_ATTEMPTS} failed: {err}")
                    except Exception as e:
                        logmsg(f"[reconnect] attempt {attempt}/{MAX_RECONNECT_ATTEMPTS} raised: {e}")
                    if attempt < MAX_RECONNECT_ATTEMPTS:
                        await asyncio.sleep(backoff)
                        backoff = min(backoff * 2, 30)
                else:
                    logmsg(f"{Colors.RED}[reconnect] all {MAX_RECONNECT_ATTEMPTS} attempts failed; "
                           f"will retry in {RECONNECT_CHECK_INTERVAL}s.{Colors.RESET}")
        except Exception as e:
            log_exception("auto_reconnect_loop", e)
        # انتظار قابل للإيقاف
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=RECONNECT_CHECK_INTERVAL)
        except asyncio.TimeoutError:
            pass


async def connect_quotex(email: str, password: str, max_attempts: int = 3,
                         proxies: Optional[str] = None) -> Optional[Quotex]:
    """يتصل بـ Quotex ويعيد كائن Quotex. يُعيد None عند الفشل.

    المعاملات:
      email      : بريد Quotex
      password   : كلمة المرور
      max_attempts: عدد محاولات الاتصال
      proxies    : URL البروكسي (مثل "http://1.2.3.4:8080" أو "socks5://1.2.3.4:1080")
    """
    for attempt in range(1, max_attempts + 1):
        try:
            client = Quotex(email=email, password=password,
                            host="quotex.com", lang="en",  # <--- تم التحديث هنا
                            proxies=proxies)
            check, reason = await client.connect()
            if check:
                try:
                    await client.change_account("PRACTICE")
                    await asyncio.sleep(0.5)
                except Exception:
                    pass
                logmsg(f"Connected to Quotex as {email}")
                return client
            else:
                err = str(reason) if reason else "Unknown error"
                logmsg(f"Login attempt {attempt}/{max_attempts} failed: {err}")
        except Exception as e:
            logmsg(f"Login attempt {attempt}/{max_attempts} raised: {e}")
        if attempt < max_attempts:
            await asyncio.sleep(3 * attempt)
    return None

# ============================================================================
# SECTION 2: EXTENDED COLOR SYSTEM + FORMATTING HELPERS
# ============================================================================

# SECTION 2: COLOR SYSTEM + FORMATTING HELPERS
# ============================================================================
class C2:
    """Extended color system."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    HIDDEN = '\033[8m'
    STRIKE = '\033[9m'

    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    BG_BRIGHT_BLACK = '\033[100m'
    BG_BRIGHT_RED = '\033[101m'
    BG_BRIGHT_GREEN = '\033[102m'
    BG_BRIGHT_YELLOW = '\033[103m'
    BG_BRIGHT_BLUE = '\033[104m'
    BG_BRIGHT_MAGENTA = '\033[105m'
    BG_BRIGHT_CYAN = '\033[106m'
    BG_BRIGHT_WHITE = '\033[107m'


def paint(color: str, text: str) -> str:
    return f"{color}{text}{C2.RESET}"


def paint_bold(text: str, color: str = C2.WHITE) -> str:
    return f"{C2.BOLD}{color}{text}{C2.RESET}"


def paint_dim(text: str) -> str:
    return f"{C2.DIM}{text}{C2.RESET}"


def visible_length(s: str) -> int:
    import re
    return len(re.sub(r'\x1b\[[0-9;]*m', '', s))


def pad_visible(s: str, width: int) -> str:
    gap = max(0, width - visible_length(s))
    return s + ' ' * gap


def hr(width: int = 80, char: str = '─', color: str = C2.DIM) -> str:
    return paint(color, char * width)


def progress_bar(progress: float, width: int = 30, fill: str = '█',
                 empty: str = '░', color_fill: str = C2.BRIGHT_GREEN,
                 color_empty: str = C2.DIM) -> str:
    filled = int(width * progress)
    bar = paint(color_fill, fill * filled) + paint(color_empty, empty * (width - filled))
    pct = f"{progress * 100:5.1f}%"
    return f"[{bar}] {pct}"


# ============================================================================
# SECTION 3: ASCII ART BANNER
# ============================================================================
BANNER_ART = r"""
██╗  ██╗██████╗  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
██║ ██╔╝██╔══██╗██╔═══██╗██║ ██╔╝██╔═══██╗██╔════╝╚══██╔══╝
█████╔╝ ██████╔╝██║   ██║█████╔╝ ██║   ██║███████╗   ██║
██╔═██╗ ██╔══██╗██║   ██║██╔═██╗ ██║   ██║╚════██║   ██║
██║  ██╗██║  ██║╚██████╔╝██║  ██╗╚██████╔╝███████║   ██║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
"""


def print_banner():
    print(paint(C2.BRIGHT_CYAN, BANNER_ART))
    print(hr(70, '═', C2.BRIGHT_BLUE))
    print(paint_bold("  Quotex Mega Fetcher — Full Engine", C2.BRIGHT_WHITE))
    print(paint_dim("  500 candles · profit % · gap-fill · live price · never-sleep"))
    print(hr(70, '═', C2.BRIGHT_BLUE))
    print(f"  {paint('Output dir:', C2.DIM)}       {paint(str(CANDLES_DIR.absolute()), C2.BRIGHT_YELLOW)}")
    print(f"  {paint('Target count:', C2.DIM)}     {paint('500 candles per asset', C2.BRIGHT_GREEN)}")
    print(f"  {paint('Default assets:', C2.DIM)}   {paint(f'{len(OTC_ASSETS)} OTC pairs', C2.BRIGHT_GREEN)}")
    print(f"  {paint('Gap-filling:', C2.DIM)}      {paint('ENABLED', C2.BRIGHT_GREEN)} (max_gap=1440 slots)")
    print(f"  {paint('Live price:', C2.DIM)}       {paint('ENABLED', C2.BRIGHT_GREEN)} (depth/follow + quotes/stream)")
    print(f"  {paint('Profit %:', C2.DIM)}         {paint('ENABLED', C2.BRIGHT_GREEN)} (instruments/list binary)")
    print(f"  {paint('Never-sleep:', C2.DIM)}      {paint('ENABLED', C2.BRIGHT_GREEN)} (keepalive + watchdog + reconnect)")
    print(hr(70, '═', C2.BRIGHT_BLUE))
    print()


# ============================================================================
# SECTION 4: EXTENDED LOGGER
# ============================================================================
class ExtendedLogger:
    """Logger that writes both to console (colored) and to file (plain)."""

    def __init__(self, log_file: str = "mega_fetch.log"):
        self.log_file = Path(log_file)
        self._lock = threading.Lock()

    def _time(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _write_file(self, level: str, msg: str):
        try:
            with self._lock:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{level}] {self._time()} - {msg}\n")
        except Exception:
            pass

    def info(self, msg: str):
        ts = self._time()
        print(f"{paint(C2.DIM, '[INFO]')} {paint(C2.BRIGHT_CYAN, ts)} "
              f"{paint(C2.DIM, '-')} {paint(C2.WHITE, msg)}")
        self._write_file("INFO", msg)

    def success(self, msg: str):
        ts = self._time()
        print(f"{paint(C2.BOLD + C2.BRIGHT_GREEN, '[OK]')} {paint(C2.BRIGHT_CYAN, ts)} "
              f"{paint(C2.DIM, '-')} {paint(C2.BRIGHT_GREEN, msg)}")
        self._write_file("OK", msg)

    def warn(self, msg: str):
        ts = self._time()
        print(f"{paint(C2.BOLD + C2.BRIGHT_YELLOW, '[WARN]')} {paint(C2.BRIGHT_CYAN, ts)} "
              f"{paint(C2.DIM, '-')} {paint(C2.BRIGHT_YELLOW, msg)}")
        self._write_file("WARN", msg)

    def error(self, msg: str):
        ts = self._time()
        print(f"{paint(C2.BOLD + C2.BRIGHT_RED, '[ERROR]')} {paint(C2.BRIGHT_CYAN, ts)} "
              f"{paint(C2.DIM, '-')} {paint(C2.BRIGHT_RED, msg)}")
        self._write_file("ERROR", msg)

    def debug(self, msg: str):
        ts = self._time()
        print(f"{paint(C2.DIM, '[DBG]')} {paint(C2.BRIGHT_CYAN, ts)} "
              f"{paint(C2.DIM, '-')} {paint(C2.DIM, msg)}")


elog = ExtendedLogger()


# ============================================================================
# SECTION 5: SPINNER
# ============================================================================
class Spinner:
    FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    FRAMES_DOTS = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
    FRAMES_CIRCLE = ['◐', '◓', '◑', '◒']

    def __init__(self, text: str = '', style: str = 'braille'):
        self.text = text
        self.frames = {
            'braille': self.FRAMES,
            'dots': self.FRAMES_DOTS,
            'circle': self.FRAMES_CIRCLE,
        }.get(style, self.FRAMES)
        self.i = 0
        self.timer = None
        self._stop_event = threading.Event()

    def start(self, text: Optional[str] = None):
        if text is not None:
            self.text = text
        if self.timer is not None:
            return self
        sys.stdout.write('\x1b[?25l')
        self._stop_event.clear()
        self.timer = threading.Thread(target=self._run, daemon=True)
        self.timer.start()
        return self

    def _run(self):
        while not self._stop_event.is_set():
            frame = paint(C2.BRIGHT_CYAN, self.frames[self.i])
            self.i = (self.i + 1) % len(self.frames)
            sys.stdout.write(f'\r{frame} {paint(C2.DIM, self.text)}\x1b[K')
            sys.stdout.flush()
            time.sleep(0.08)

    def update(self, text: str):
        self.text = text

    def stop(self, final_msg: Optional[str] = None, success: bool = True):
        if self.timer is None:
            return
        self._stop_event.set()
        self.timer.join(timeout=0.5)
        self.timer = None
        sys.stdout.write('\r\x1b[K')
        sys.stdout.write('\x1b[?25h')
        sys.stdout.flush()
        if final_msg:
            if success:
                elog.success(final_msg)
            else:
                elog.error(final_msg)


# ============================================================================
# SECTION 6: CONFIGURATION
# ============================================================================
TARGET_CANDLE_COUNT = 500
TIMEFRAME_DEFAULT = 1
GAP_FILL_MAX_SLOTS = 1440

# Never-sleep engine timings (ported from wedsoket_.py)
KEEPALIVE_PING_INTERVAL = 5         # seconds between pings
STALE_MESSAGE_TIMEOUT = 45         # if no message for 45s, recycle connection
STALE_WATCHDOG_INTERVAL = 10       # check every 10s
HEALTH_CHECK_INTERVAL = 20         # health monitor every 20s
RECONNECT_CHECK_INTERVAL = 10      # reconnect check every 10s
MAX_RECONNECT_ATTEMPTS = 8         # attempts before giving up (was 5, increased)
RECONNECT_BACKOFF_BASE = 3         # initial backoff in seconds
RECONNECT_BACKOFF_MAX = 60         # maximum backoff
LONG_DISCONNECT_THRESHOLD = 3600   # 1 hour — triggers full re-fetch

# Live price settings
LIVE_PRICE_LISTEN_SECONDS = 5.0    # how long to listen for ticks per asset (was 2)
LIVE_PRICE_BROADCAST_INTERVAL = 0.5  # render interval for live price table

# DEBUG: when True, every WS message is logged for diagnosis.
# Disable by setting this to False in production.
DEBUG_WS_TRAFFIC = True
DEBUG_BINARY_PREVIEW_BYTES = 32
DEBUG_TEXT_PREVIEW_CHARS = 200

# Fetch strategy
CHUNK_CANDLES = 60
OVERLAP_CANDLES = 10
FETCH_BATCH_SIZE = 4
FETCH_STAGGER_MS = 150

# The 13 OTC pairs
OTC_ASSETS = [
    "BRLUSD_otc",   # Brazil
    "USDARS_otc",   # Argentina
    "USDBDT_otc",   # Bangladesh
    "USDCOP_otc",   # Colombia
    "USDDZD_otc",   # Algeria
    "USDEGP_otc",   # Egypt
    "USDIDR_otc",   # Indonesia
    "USDINR_otc",   # India
    "USDMXN_otc",   # Mexico
    "USDNGN_otc",   # Nigeria
    "USDPHP_otc",   # Philippines
    "USDPKR_otc",   # Pakistan
    "USDZAR_otc",   # South Africa
]


# ============================================================================
# SECTION 7: GAP-FILLING ENGINE (ported verbatim from wedsoket_.py)
# ============================================================================
def _fill_missing_slots(candles: List[Dict], period_seconds: int,
                        max_gap: int = GAP_FILL_MAX_SLOTS) -> List[Dict]:
    """Fills time gaps between candles with flat candles (previous close).

    Ported verbatim from wedsoket_.py.
    - Added candles have volume=0 (marked synthetic).
    - max_gap: max number of periods to fill (1440 = 1 day for M1).
    """
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


# ============================================================================
# SECTION 8: MESSAGE INTERCEPTOR (instruments + candles + live ticks)
# ============================================================================
class MessageInterceptor:
    """Intercepts WebsocketClient.on_message to capture:

    (a) binary instruments/list frames (JSON, 0x04-prefixed) → profit %, enabled
    (b) live tick arrays (quotes/stream, depth/change) → current price
    (c) historical candle responses (history/load, history/list/v2) → candles

    All captured data is stored in the `state` dict and surfaced via
    asyncio events.
    """

    def __init__(self, client: Quotex):
        self.client = client
        self.instruments: List[Dict] = []
        self.profit_by_asset: Dict[str, int] = {}  # asset → profit %
        self.enabled_by_asset: Dict[str, bool] = {}
        self.live_prices: Dict[str, float] = {}
        self.live_ticks_seen: Dict[str, int] = defaultdict(int)
        self.last_tick_at: Dict[str, float] = {}

        self.instruments_ready = asyncio.Event()
        self.candles_ready: Dict[str, asyncio.Event] = defaultdict(asyncio.Event)
        self.candles_data: Dict[str, List[Dict]] = {}

        self._original_on_message = None
        self._ws_client = None
        self._expecting_instruments_binary = False
        self._temp_status_instruments = ""
        self._temp_status_history = ""  # tracks which asset we're awaiting

    def install(self) -> bool:
        api = self.client.api
        if api is None:
            return False
        ws_client = getattr(api, "websocket_client", None)
        if ws_client is None:
            return False
        self._ws_client = ws_client
        self._original_on_message = ws_client.on_message
        ws_client.on_message = self._on_message
        elog.info("[interceptor] installed on WebsocketClient.on_message")
        return True

    def restore(self) -> None:
        try:
            if self._ws_client is not None and self._original_on_message is not None:
                self._ws_client.on_message = self._original_on_message
                elog.info("[interceptor] original handler restored")
        except Exception:
            pass

    def _on_message(self, wss, msg) -> None:
        """Capture binary frames + tick arrays; chain text to original.

        With DEBUG_WS_TRAFFIC enabled, every frame is logged for diagnosis:
          - text frames: size + first DEBUG_TEXT_PREVIEW_CHARS chars
          - binary frames: size + first DEBUG_BINARY_PREVIEW_BYTES hex bytes
                            + UTF-8 preview (after 0x04 strip)
        """
        # === DEBUG LOGGING ===
        if DEBUG_WS_TRAFFIC:
            try:
                if isinstance(msg, (bytes, bytearray)):
                    raw = bytes(msg)
                    preview_hex = raw[:DEBUG_BINARY_PREVIEW_BYTES].hex(' ')
                    utf8_preview = ""
                    if len(raw) > 0:
                        offset = 1 if raw[0] == 0x04 else 0
                        utf8_preview = raw[offset:offset + 100].decode('utf-8', errors='replace')
                    elog.debug(f"[ws-debug] BINARY {len(raw):,}B | hex: {preview_hex} | utf8: {utf8_preview!r}")
                else:
                    text = msg if isinstance(msg, str) else msg.decode("utf-8", errors="ignore")
                    preview = text[:DEBUG_TEXT_PREVIEW_CHARS]
                    trunc = "…" if len(text) > DEBUG_TEXT_PREVIEW_CHARS else ""
                    elog.debug(f"[ws-debug] TEXT {len(text):,}c | {preview!r}{trunc}")
            except Exception as e:
                elog.debug(f"[ws-debug] preview error: {e}")

        # === CAPTURE ===
        if isinstance(msg, (bytes, bytearray)):
            self._try_capture_binary(bytes(msg))
        else:
            text = msg if isinstance(msg, str) else msg.decode("utf-8", errors="ignore")
            # Detect instruments/list announcement
            if "_placeholder" in text and "instruments/list" in text:
                if not self._expecting_instruments_binary:
                    self._expecting_instruments_binary = True
                    elog.info("[interceptor] received 451-['instruments/list',{...}] announcement; "
                              "expecting binary frame next")
                self._temp_status_instruments = text
            # Detect history/load announcement (response with binary attachment)
            elif "_placeholder" in text and ("history/list" in text or "history/load" in text):
                self._temp_status_history = text
            # Try to extract live ticks from EVERY text frame (not just '42'-prefixed)
            self._try_extract_ticks_from_text(text)

        # === CHAIN TO ORIGINAL ===
        if self._original_on_message is not None:
            try:
                self._original_on_message(wss, msg)
            except Exception as e:
                elog.debug(f"[interceptor] original on_message raised: {e}")

    def _try_capture_binary(self, data: bytes) -> None:
        """Try to decode a binary frame as JSON (with 0x04 strip) or msgpack.

        Ported and enhanced from wedsoket_.py's _onMessage pattern:
          1. Strip leading 0x04 byte (Engine.IO binary marker)
          2. Find first '[' or '{' and JSON-parse the rest
          3. Fallback to msgpack if JSON fails

        Handles BOTH instrument formats Quotex may send:
          - Dict form:  [{"asset":"USDARS_otc","profit":92,"enabled":true}, ...]
          - Array form: [[1,"USDARS_otc","USD/ARS",...,92,...,true], ...]
        """
        # Lower threshold (was 128) — some binary frames are smaller
        if len(data) < 32:
            return

        decoded = None
        decode_strategy = "none"

        # Strategy 1: strip 0x04, then JSON (the working Node.js pattern)
        candidate = data[1:] if data[0] == 0x04 else data
        try:
            text = candidate.decode("utf-8", errors="ignore")
            start_idx = -1
            for i, ch in enumerate(text):
                if ch in ('[', '{'):
                    start_idx = i
                    break
            if start_idx >= 0:
                parsed = json.loads(text[start_idx:])
                if parsed is not None:
                    decoded = parsed
                    decode_strategy = "json+0x04-strip"
        except Exception:
            pass

        # Strategy 2: raw JSON (no byte strip)
        if decoded is None:
            try:
                text = data.decode("utf-8", errors="ignore")
                start_idx = -1
                for i, ch in enumerate(text):
                    if ch in ('[', '{'):
                        start_idx = i
                        break
                if start_idx >= 0:
                    parsed = json.loads(text[start_idx:])
                    if parsed is not None:
                        decoded = parsed
                        decode_strategy = "json-raw"
            except Exception:
                pass

        # Strategy 3: msgpack fallback (rare, but possible)
        if decoded is None:
            try:
                import msgpack
                decoded = msgpack.unpackb(data, raw=False, strict_map_key=False)
                decode_strategy = "msgpack"
            except Exception:
                pass

        if decoded is None:
            # Debug: log unrecognized binary frames
            if len(data) >= 100:
                preview_hex = data[:32].hex(' ')
                elog.debug(f"[binary] unrecognized frame: {len(data)} bytes, "
                           f"hex: {preview_hex}")
            return

        # Route the decoded payload
        # Case A: instruments/list (expected or auto-detected)
        if self._expecting_instruments_binary or self._looks_like_instruments(decoded):
            self._handle_instruments(decoded, decode_strategy, len(data))
            self._expecting_instruments_binary = False
            self._temp_status_instruments = ""
            return

        # Case B: historical candles (history/load response)
        if self._temp_status_history or self._looks_like_history(decoded):
            self._handle_history(decoded)
            self._temp_status_history = ""
            return

    @staticmethod
    def _looks_like_instruments(data: Any) -> bool:
        """Heuristic: is this a list of instrument dicts OR arrays?

        Supports both formats Quotex may send:
          - Dict form:  [{"asset":"USDARS_otc","profit":92,...}, ...]
          - Array form: [[1,"USDARS_otc","USD/ARS",...,92,...,true], ...]
        """
        if not isinstance(data, list) or len(data) < 5:
            return False
        sample = data[:5]

        # Dict form: each item must be a dict with asset/id/symbol/name
        if all(isinstance(item, dict) for item in sample):
            for item in sample:
                if not any(k in item for k in ("asset", "id", "symbol", "name")):
                    return False
            return True

        # Array form: each item must be a list with >= 6 elements
        # (id, symbol, name, type, ..., payout, ..., open)
        if all(isinstance(item, list) and len(item) >= 6 for item in sample):
            # Second element should be a string (asset name)
            if all(isinstance(item[1], str) for item in sample):
                return True

        return False

    @staticmethod
    def _looks_like_history(data: Any) -> bool:
        if not isinstance(data, list) or len(data) < 1:
            return False
        first = data[0]
        if isinstance(first, dict) and 'time' in first:
            return True
        if isinstance(first, list) and len(first) >= 5:
            return True
        return False

    def _handle_instruments(self, data: Any, strategy: str, size: int) -> None:
        """Process the instruments list and extract profit % per asset.

        Handles BOTH formats (mirrors wedsoket_.py's printAssetsTable logic):
          - Dict form:  item.get("profit") or item.get("payout")
          - Array form:  item[5] (payout at index 5)
        And enabled status:
          - Dict form:  item.get("enabled") or item.get("open") or item.get("isOpen")
          - Array form: item[14] (open flag at index 14)
        """
        # Unwrap Socket.IO envelope if present
        if isinstance(data, list) and len(data) == 2 and isinstance(data[0], str):
            data = data[1]
        if isinstance(data, dict):
            if isinstance(data.get("instruments"), list):
                data = data["instruments"]
            elif isinstance(data.get("list"), list):
                data = data["list"]

        if not isinstance(data, list):
            return

        self.instruments = data
        dict_count = 0
        array_count = 0
        for item in data:
            # === Dict form ===
            if isinstance(item, dict):
                dict_count += 1
                # Asset name: try multiple field names
                asset = (item.get("asset") or item.get("name") or
                         item.get("symbol") or item.get("id"))
                # Profit %: try "profit" then "payout"
                profit = item.get("profit")
                if profit is None:
                    profit = item.get("payout")
                # Enabled: try "enabled", "open", "isOpen"
                enabled = None
                for k in ("enabled", "open", "isOpen"):
                    if k in item:
                        enabled = bool(item[k])
                        break
                if asset:
                    if profit is not None:
                        try:
                            self.profit_by_asset[asset] = int(profit)
                        except (ValueError, TypeError):
                            try:
                                self.profit_by_asset[asset] = int(float(profit))
                            except Exception:
                                pass
                    if enabled is not None:
                        self.enabled_by_asset[asset] = enabled

            # === Array form: [id, symbol, name, type, ..., payout(5), ..., open(14)] ===
            elif isinstance(item, list) and len(item) >= 6:
                array_count += 1
                # item[1] = symbol/asset name
                asset = item[1] if isinstance(item[1], str) else None
                # item[5] = payout percentage
                profit = item[5] if len(item) > 5 else None
                # item[14] = open flag
                enabled = bool(item[14]) if len(item) > 14 else None
                if asset:
                    if profit is not None:
                        try:
                            self.profit_by_asset[asset] = int(profit)
                        except (ValueError, TypeError):
                            try:
                                self.profit_by_asset[asset] = int(float(profit))
                            except Exception:
                                pass
                    if enabled is not None:
                        self.enabled_by_asset[asset] = enabled

        elog.success(f"[instruments] captured via {strategy}: {len(data)} entries "
                     f"({dict_count} dict, {array_count} array), "
                     f"{len(self.profit_by_asset)} profit %, {size:,} bytes")
        if not self.instruments_ready.is_set():
            self.instruments_ready.set()

    def _handle_history(self, data: Any) -> None:
        """Process a historical candles response."""
        # Unwrap envelope
        if isinstance(data, list) and len(data) == 2 and isinstance(data[0], str):
            payload = data[1]
            if isinstance(payload, dict):
                asset = payload.get("asset") or payload.get("symbol")
                candles = payload.get("history") or payload.get("data") or payload.get("candles") or []
                if asset and candles:
                    self.candles_data[asset] = candles
                    self.candles_ready[asset].set()
                return
            if isinstance(payload, list):
                # No asset identifier; best-effort: store under "last"
                self.candles_data["_last"] = payload
                self.candles_ready["_last"].set()
                return
        elif isinstance(data, dict):
            asset = data.get("asset") or data.get("symbol")
            candles = data.get("history") or data.get("data") or data.get("candles") or []
            if asset and candles:
                self.candles_data[asset] = candles
                self.candles_ready[asset].set()
            return
        elif isinstance(data, list) and data and isinstance(data[0], list):
            # Bare list of candle arrays
            self.candles_data["_last"] = data
            self.candles_ready["_last"].set()
            return

    def _try_extract_ticks_from_text(self, text: str) -> None:
        """Extract live price ticks from any text frame.

        Tries multiple Quotex message formats:
          42["quotes/stream",[[asset, time, price], ...]]
          42["depth/change",[[asset, time, price], ...]]
          42[<event>,[[asset, time, price], ...]]
          42[<event>,{"data":[[asset, time, price], ...]}]

        Also handles raw JSON arrays (no Socket.IO prefix):
          [[asset, time, price], ...]
        """
        # Try to find ANY JSON array/object in the text and parse it.
        # The Socket.IO prefix (42, 451-, etc.) may or may not be present.
        # We search for the first '[' or '{' character.
        start_idx = -1
        for i, ch in enumerate(text):
            if ch in ('[', '{'):
                start_idx = i
                break
        if start_idx < 0:
            return

        try:
            json_str = text[start_idx:]
            parsed = json.loads(json_str)
        except Exception:
            return

        if parsed is None:
            return

        # Route to _extract_ticks which handles all payload shapes.
        # _extract_ticks handles both bare lists and Socket.IO envelopes.
        self._extract_ticks(parsed)

    def _extract_ticks(self, payload: Any) -> None:
        """Look for tick arrays in the payload and record prices.

        Handles ALL of these shapes (mirrors wedsoket_.py's tick handling):
          1. [[asset, time, price], ...]                    (bare list of ticks)
          2. ["quotes/stream", [[asset, time, price], ...]]  (Socket.IO envelope)
          3. {"asset": asset, "price": price, ...}           (single tick dict)
          4. {"data": [[asset, time, price], ...]}           (wrapped in 'data')
          5. [event_name, {"data": [...]}]                   (envelope + wrapper)
        """
        candidates = []

        # Shape 1: bare list of ticks
        if isinstance(payload, list):
            if payload and isinstance(payload[0], list):
                candidates = payload
            # Shape 2: Socket.IO envelope [event_name, payload]
            elif payload and isinstance(payload[0], str) and len(payload) >= 2:
                inner = payload[1]
                # Inner could be a list of ticks
                if isinstance(inner, list) and inner and isinstance(inner[0], list):
                    candidates = inner
                # Inner could be a dict with 'data' key (Shape 5)
                elif isinstance(inner, dict) and isinstance(inner.get("data"), list):
                    candidates = inner["data"]
                # Inner could be a single tick dict (Shape 3)
                elif isinstance(inner, dict) and "asset" in inner and "price" in inner:
                    candidates = [inner]

        # Shape 3: single tick dict at top level
        elif isinstance(payload, dict):
            if "asset" in payload and "price" in payload:
                candidates = [payload]
            # Shape 4: wrapped in 'data' key
            elif isinstance(payload.get("data"), list):
                candidates = payload["data"]

        # Extract prices from candidates
        new_ticks = 0
        for tick in candidates:
            if isinstance(tick, list) and len(tick) >= 3:
                asset = tick[0]
                price = tick[2]
                if isinstance(asset, str) and isinstance(price, (int, float)):
                    self.live_prices[asset] = float(price)
                    self.live_ticks_seen[asset] += 1
                    self.last_tick_at[asset] = time.time()
                    new_ticks += 1
            elif isinstance(tick, dict) and "asset" in tick and "price" in tick:
                asset = tick["asset"]
                price = tick["price"]
                if isinstance(asset, str) and isinstance(price, (int, float)):
                    self.live_prices[asset] = float(price)
                    self.live_ticks_seen[asset] += 1
                    self.last_tick_at[asset] = time.time()
                    new_ticks += 1

        if new_ticks > 0 and DEBUG_WS_TRAFFIC:
            elog.debug(f"[ticks] captured {new_ticks} new ticks "
                       f"(total assets tracked: {len(self.live_prices)})")

    # === Public API ===
    def get_profit(self, asset: str) -> Optional[int]:
        return self.profit_by_asset.get(asset)

    def get_enabled(self, asset: str) -> Optional[bool]:
        return self.enabled_by_asset.get(asset)

    def get_live_price(self, asset: str) -> Optional[float]:
        return self.live_prices.get(asset)

    def get_stats(self, asset: str) -> Dict[str, Any]:
        return {
            'price': self.live_prices.get(asset),
            'ticks_seen': self.live_ticks_seen.get(asset, 0),
            'last_tick_ago': time.time() - self.last_tick_at[asset]
                             if asset in self.last_tick_at else None,
            'profit': self.profit_by_asset.get(asset),
            'enabled': self.enabled_by_asset.get(asset),
        }


# ============================================================================
# SECTION 9: NEVER-SLEEP ENGINE (ported from wedsoket_.py)
# ============================================================================
class NeverSleepEngine:
    """Runs four background asyncio tasks to keep the connection alive:

    1. keepalive_loop: ping every KEEPALIVE_PING_INTERVAL seconds
    2. stale_message_watchdog: detect silent connection (no msgs for 45s)
    3. auto_reconnect: rebuild connection on loss (exponential backoff)
    4. health_monitor: periodic state check (every 20s)

    All four loops are cancellable via stop_event.
    """

    def __init__(self, client_holder: 'ClientHolder', interceptor: MessageInterceptor):
        self.client_holder = client_holder
        self.interceptor = interceptor
        self.stop_event = asyncio.Event()
        self.tasks: List[asyncio.Task] = []
        self.connection_alive = True
        self.last_ping_at = 0.0
        self.last_message_at = time.time()
        self.connection_drops = 0
        self.last_drop_time = 0.0
        self.uptime_start = time.time()
        self.is_reconnecting = False

    def start(self):
        self.tasks = [
            asyncio.create_task(self.keepalive_loop()),
            asyncio.create_task(self.stale_message_watchdog()),
            asyncio.create_task(self.auto_reconnect()),
            asyncio.create_task(self.health_monitor()),
        ]
        elog.info("[never-sleep] background engine started (4 tasks)")

    async def stop(self):
        self.stop_event.set()
        for t in self.tasks:
            try:
                await asyncio.wait_for(t, timeout=2.0)
            except Exception:
                pass
        self.tasks.clear()

    def _mark_message_received(self):
        """Called by interceptor when any message arrives."""
        self.last_message_at = time.time()

    async def keepalive_loop(self):
        """Ping every KEEPALIVE_PING_INTERVAL seconds.

        Ported from wedsoket_.py:keepalive_loop.
        Sends engine.io ping ("2") + application tick ('42["tick"]')
        + periodically instruments/get to refresh the asset list.
        """
        tick_count = 0
        while not self.stop_event.is_set():
            await asyncio.sleep(0.5)
            now = time.time()
            if now - self.last_ping_at < KEEPALIVE_PING_INTERVAL:
                continue
            self.last_ping_at = now
            client = self.client_holder.client
            if client is None or client.api is None:
                continue
            try:
                # engine.io ping
                client.api.send_websocket_request("2", no_force_send=False)
                # application tick
                client.api.send_websocket_request('42["tick"]', no_force_send=False)
                # periodic instruments refresh (every 3rd ping)
                if tick_count % 3 == 0:
                    client.api.send_websocket_request('42["instruments/get"]', no_force_send=False)
                tick_count += 1
            except Exception as e:
                elog.debug(f"[keepalive] ping failed: {e}")

    async def stale_message_watchdog(self):
        """Recycle connection if no messages for STALE_MESSAGE_TIMEOUT seconds.

        Ported from wedsoket_.py:stale_message_watchdog.
        """
        while not self.stop_event.is_set():
            await asyncio.sleep(STALE_WATCHDOG_INTERVAL)
            client = self.client_holder.client
            if client is None or client.api is None:
                continue
            try:
                # Update last_message_at from the API's own tracking
                api_last = getattr(client.api, 'last_message_at', None)
                if api_last is not None:
                    self.last_message_at = api_last

                silent_for = time.time() - self.last_message_at
                if silent_for > STALE_MESSAGE_TIMEOUT:
                    elog.warn(f"[watchdog] no messages for {silent_for:.1f}s "
                              f"(>{STALE_MESSAGE_TIMEOUT}s); recycling connection")
                    if self.last_drop_time == 0:
                        self.last_drop_time = time.time()
                    self.connection_alive = False
                    # Force-close WS to trigger on_close → auto_reconnect
                    try:
                        ws_client = getattr(client.api, 'websocket_client', None)
                        if ws_client and ws_client.wss:
                            ws_client.wss.close()
                    except Exception:
                        pass
            except Exception as e:
                elog.debug(f"[watchdog] error: {e}")

    async def auto_reconnect(self):
        """Rebuild connection on loss with exponential backoff.

        Ported from wedsoket_.py:auto_reconnect.
        """
        while not self.stop_event.is_set():
            await asyncio.sleep(RECONNECT_CHECK_INTERVAL)
            # Record drop time if not already set
            if not self.connection_alive and self.last_drop_time == 0:
                self.last_drop_time = time.time()
                elog.info(f"[reconnect] connection loss detected at {self.last_drop_time:.0f}")

            if self.connection_alive or self.is_reconnecting:
                continue

            self.is_reconnecting = True
            try:
                h = self.client_holder
                backoff = RECONNECT_BACKOFF_BASE
                for attempt in range(1, MAX_RECONNECT_ATTEMPTS + 1):
                    if self.stop_event.is_set():
                        return
                    try:
                        elog.info(f"[reconnect] attempt {attempt}/{MAX_RECONNECT_ATTEMPTS}")
                        new_client = Quotex(
                            email=h.email, password=h.password,
                            host="quotex.com", lang="en", proxies=h.proxies,
                        )
                        check, reason = await new_client.connect()
                        if check:
                            try:
                                await new_client.change_account("PRACTICE")
                                await asyncio.sleep(0.5)
                            except Exception:
                                pass
                            # Close old client
                            try:
                                if self.client_holder.client:
                                    await self.client_holder.client.close()
                            except Exception:
                                pass
                            # Swap in new client
                            self.client_holder.client = new_client
                            # Re-install interceptor on new WS client
                            self.interceptor.client = new_client
                            self.interceptor.install()
                            self.connection_alive = True
                            self.last_drop_time = 0
                            self.connection_drops += 1
                            self.last_message_at = time.time()
                            drop_duration = time.time() - (self.last_drop_time or time.time())
                            elog.success(f"[reconnect] reconnect successful on attempt {attempt}")
                            if drop_duration > LONG_DISCONNECT_THRESHOLD:
                                elog.warn(f"[reconnect] LONG disconnect detected "
                                          f"({drop_duration/60:.1f} min) — may need full re-fetch")
                            break
                        else:
                            err = str(reason) if reason else "Unknown"
                            elog.warn(f"[reconnect] attempt {attempt} failed: {err}")
                    except Exception as e:
                        elog.warn(f"[reconnect] attempt {attempt} raised: {e}")
                    if attempt < MAX_RECONNECT_ATTEMPTS:
                        await asyncio.sleep(backoff)
                        backoff = min(backoff * 2, RECONNECT_BACKOFF_MAX)
                else:
                    elog.error(f"[reconnect] all {MAX_RECONNECT_ATTEMPTS} attempts failed; "
                               f"will retry in {RECONNECT_CHECK_INTERVAL}s")
            finally:
                self.is_reconnecting = False

    async def health_monitor(self):
        """Periodic health check (every HEALTH_CHECK_INTERVAL seconds).

        Ported from wedsoket_.py:health_monitor.
        """
        while not self.stop_event.is_set():
            await asyncio.sleep(HEALTH_CHECK_INTERVAL)
            client = self.client_holder.client
            if client is None or client.api is None:
                continue
            try:
                state = getattr(client.api, 'state', None)
                if state is None:
                    continue
                alive = bool(getattr(state, 'check_accepted_connection', False))
                if not alive and self.connection_alive:
                    elog.warn("[health] connection marked dead by health monitor")
                    self.connection_alive = False
                    if self.last_drop_time == 0:
                        self.last_drop_time = time.time()
                elif alive and not self.connection_alive:
                    # State says alive but we thought it was dead — refresh
                    self.connection_alive = True
                    self.last_drop_time = 0
                    elog.success("[health] connection restored (state confirms)")
            except Exception as e:
                elog.debug(f"[health] error: {e}")

    def stats(self) -> Dict[str, Any]:
        return {
            'uptime_seconds': time.time() - self.uptime_start,
            'connection_alive': self.connection_alive,
            'connection_drops': self.connection_drops,
            'last_drop_ago': time.time() - self.last_drop_time if self.last_drop_time else None,
            'last_ping_ago': time.time() - self.last_ping_at if self.last_ping_at else None,
            'last_message_ago': time.time() - self.last_message_at,
            'is_reconnecting': self.is_reconnecting,
        }


# ============================================================================
# SECTION 10: CLIENT HOLDER
# ============================================================================
class ClientHolder:
    """Holds the active Quotex client. Allows swapping on reconnect."""

    def __init__(self, client: Optional[Quotex], email: str = '', password: str = '',
                 proxies: Optional[str] = None):
        self.client = client
        self.email = email
        self.password = password
        self.proxies = proxies
        self.label = email or 'N/A'


# ============================================================================
# SECTION 11: LIVE PRICE SUBSCRIBER
# ============================================================================
class LivePriceSubscriber:
    """Subscribes to live price updates for one or more assets.

    Uses the same subscription messages as wedsoket_.py:
      42["instruments/update",{"asset":"ASSET_otc","period":60}]
      42["depth/follow","ASSET_otc"]
      42["chart_notification/get"]
    """

    def __init__(self, interceptor: MessageInterceptor):
        self.interceptor = interceptor
        self.subscribed_assets: set = set()

    def subscribe(self, asset: str, period: int = 60) -> None:
        api = self.interceptor.client.api
        try:
            api.send_websocket_request(
                f'42["instruments/update",{{"asset":"{asset}","period":{period}}}]',
                no_force_send=False,
            )
            api.send_websocket_request(f'42["depth/follow","{asset}"]', no_force_send=False)
            api.send_websocket_request('42["chart_notification/get"]', no_force_send=False)
            self.subscribed_assets.add(asset)
        except Exception as e:
            elog.warn(f"[live] failed to subscribe {asset}: {e}")

    def subscribe_all(self, assets: List[str], period: int = 60) -> None:
        for asset in assets:
            self.subscribe(asset, period)

    def unsubscribe(self, asset: str) -> None:
        api = self.interceptor.client.api
        try:
            api.send_websocket_request(f'42["depth/unfollow","{asset}"]', no_force_send=False)
            self.subscribed_assets.discard(asset)
        except Exception:
            pass

    def unsubscribe_all(self) -> None:
        for asset in list(self.subscribed_assets):
            self.unsubscribe(asset)


# ============================================================================
# SECTION 12: CANDLE FETCHER (chunked, with gap-fill)
# ============================================================================
class CandleFetcher:
    """Fetches exactly N candles for an asset — same method as OTC_canda_.py.

    Instead of the broken "overlapping chunks" approach, this uses the SAME
    method as the original OTC_canda_.py:
      1. Calculate days needed: days = ceil(target_count * timeframe_min / 1440) + buffer
      2. Call client.get_historical_candles(asset, amount_of_seconds=days*86400,
         period=period_seconds, max_workers=5) — this is ONE call that fetches
         the entire span, with max_workers=5 doing parallel chunks internally.
      3. Dedup by timestamp + sort + gap-fill
      4. Truncate to last target_count candles (or pad if insufficient)
    """

    def __init__(self, client_holder: ClientHolder, interceptor: MessageInterceptor):
        self.client_holder = client_holder
        self.interceptor = interceptor

    async def fetch_exactly_n(self, asset: str, timeframe_min: int,
                              target_count: int = TARGET_CANDLE_COUNT,
                              progress: bool = True) -> List[Dict]:
        """Fetch exactly target_count candles for asset (OTC_canda_ method)."""
        import math
        period_seconds = int(timeframe_min * 60)
        display_name = f"{asset} (M{timeframe_min})"
        client = self.client_holder.client
        if client is None:
            elog.error(f"No client for {asset}")
            return []

        print(f"\n  {paint_bold('Fetching ', C2.BRIGHT_CYAN)}"
              f"{paint_bold(f'{target_count} candles', C2.BRIGHT_GREEN)} — {display_name}")

        # Calculate days needed: target_count candles * timeframe_min minutes
        # / 1440 minutes per day, +1 day buffer to ensure we get enough.
        days_needed = max(1, math.ceil(target_count * timeframe_min / 1440) + 1)
        amount_of_seconds = int(days_needed * 86400)
        # Timeout: 60s minimum, +60s per day
        timeout = max(60, days_needed * 60)
        fetch_start = time.time()

        elog.info(f"Requesting {days_needed} day(s) of {asset} history "
                  f"(~{days_needed * 1440 // timeframe_min:,} candles expected)")

        # === SINGLE CALL — same as OTC_canda_.py:fetch_candles_for_asset ===
        # This calls client.get_historical_candles which internally splits the
        # span into 5 parallel workers and waits for all to complete.
        try:
            candles_raw = await asyncio.wait_for(
                client.get_historical_candles(
                    asset,
                    amount_of_seconds=amount_of_seconds,
                    period=period_seconds,
                    max_workers=5,
                    progress_callback=None,
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            elog.error(f"Fetch timed out after {timeout}s for {asset}.")
            return []
        except Exception as e:
            elog.error(f"Fetch raised for {asset}: {e}")
            return []

        if not candles_raw:
            elog.error(f"No candles returned for {asset}.")
            return []

        elapsed = time.time() - fetch_start
        elog.info(f"Received {len(candles_raw):,} raw candles in {int(elapsed)}s")

        # === DEDUP + FORMAT (same as OTC_canda_.py) ===
        candles_map: Dict[int, Dict] = {}
        for c in candles_raw:
            if not isinstance(c, dict):
                continue
            try:
                ts = int(c.get("time", c.get("timestamp", 0)))
                aligned = (ts // period_seconds) * period_seconds
                o = float(c.get("open", 0))
                h = float(c.get("high", c.get("max", 0)))
                l = float(c.get("low", c.get("min", 0)))
                cl = float(c.get("close", 0))
                if aligned not in candles_map and o > 0 and h > 0 and l > 0 and cl > 0:
                    candles_map[aligned] = {
                        'time': aligned, 'open': o, 'high': h,
                        'low': l, 'close': cl,
                        'volume': int(c.get("volume", 0) or 0),
                    }
            except Exception:
                continue

        if not candles_map:
            elog.error(f"No valid candles after dedup for {asset}.")
            return []

        # Sort by time
        candles = sorted(candles_map.values(), key=lambda x: x['time'])
        elog.info(f"After dedup: {len(candles):,} unique candles "
                  f"({candles[0]['time']} → {candles[-1]['time']})")

        # Apply gap-filling
        before_fill = len(candles)
        candles = _fill_missing_slots(candles, period_seconds, max_gap=GAP_FILL_MAX_SLOTS)
        after_fill = len(candles)
        filled_count = after_fill - before_fill
        if filled_count > 0:
            elog.warn(f"Filled {filled_count} gap slots with flat candles for {asset}.")

        # Truncate or pad to exactly target_count
        if len(candles) > target_count:
            candles = candles[-target_count:]
            elog.info(f"Truncated to last {target_count} candles.")
        elif len(candles) < target_count:
            first_ts = candles[0]['time']
            last_close = candles[0]['open']
            deficit = target_count - len(candles)
            for i in range(deficit, 0, -1):
                candles.insert(0, {
                    'time': first_ts - i * period_seconds,
                    'open': last_close, 'high': last_close,
                    'low': last_close, 'close': last_close, 'volume': 0,
                })
            elog.warn(f"Padded {deficit} candles at the start for {asset} "
                      f"(insufficient history).")

        elapsed = time.time() - fetch_start
        elog.success(f"Fetched {len(candles)} candles in "
                     f"{int(elapsed//60):02d}:{int(elapsed%60):02d} — {display_name}")
        return candles


# ============================================================================
# SECTION 13: INSTRUMENTS FETCHER (profit %, enabled status)
# ============================================================================
class InstrumentsFetcher:
    """Fetches the instruments list to get profit % and enabled status per asset.

    Sends 42["instruments/get"] and waits for the binary response.
    The MessageInterceptor captures the response and populates
    profit_by_asset and enabled_by_asset.
    """

    def __init__(self, client_holder: ClientHolder, interceptor: MessageInterceptor):
        self.client_holder = client_holder
        self.interceptor = interceptor

    async def fetch(self, timeout: float = 30.0) -> bool:
        """Send instruments/get request and wait for response."""
        client = self.client_holder.client
        if client is None or client.api is None:
            elog.error("No client for instruments fetch.")
            return False

        # Send the request multiple times (in case of silent drop)
        requests = ['42["instruments/get"]'] * 3
        for i, req in enumerate(requests, 1):
            try:
                client.api.send_websocket_request(req, no_force_send=False)
                elog.info(f"[instruments] sent request {i}/{len(requests)}")
            except Exception as e:
                elog.warn(f"[instruments] failed to send request {i}: {e}")
            if i < len(requests):
                await asyncio.sleep(1.5)

        # Wait for the binary response
        try:
            await asyncio.wait_for(
                self.interceptor.instruments_ready.wait(),
                timeout=timeout,
            )
            return True
        except asyncio.TimeoutError:
            elog.error(f"[instruments] timeout after {timeout}s — no response")
            return False

    def get_profit(self, asset: str) -> Optional[int]:
        return self.interceptor.get_profit(asset)

    def get_enabled(self, asset: str) -> Optional[bool]:
        return self.interceptor.get_enabled(asset)

    def print_summary(self, assets: List[str]):
        """Print a summary table of profit % and enabled status for the given assets."""
        print()
        print(hr(70, '─', C2.DIM))
        print(f"  {paint_bold('📊 INSTRUMENTS SUMMARY', C2.BRIGHT_CYAN)}")
        print(hr(70, '─', C2.DIM))
        print(f"  {'Asset':<18} {'Profit %':<12} {'Status':<10} {'Live Price':<15}")
        print(hr(70, '─', C2.DIM))
        for asset in assets:
            profit = self.get_profit(asset)
            enabled = self.get_enabled(asset)
            live = self.interceptor.get_live_price(asset)
            profit_str = paint_bold(f"{profit}%", C2.BRIGHT_GREEN) if profit is not None else paint_dim("N/A")
            enabled_str = (paint_bold("OPEN", C2.BRIGHT_GREEN) if enabled
                           else paint_bold("CLOSED", C2.BRIGHT_RED) if enabled is False
                           else paint_dim("?"))
            live_str = paint_bold(f"{live:.5f}", C2.BRIGHT_CYAN) if live is not None else paint_dim("—")
            print(f"  {paint_bold(asset, C2.BRIGHT_YELLOW):<18} {profit_str:<12} {enabled_str:<10} {live_str:<15}")
        print(hr(70, '─', C2.DIM))
        print()


# ============================================================================
# SECTION 14: JSON SAVER
# ============================================================================
def save_candles_to_json(candles: List[Dict], asset: str, timeframe_min: int,
                          target_count: int, profit: Optional[int] = None) -> Optional[Path]:
    """Saves candles to candles_otc_data/{asset}_{tf}m_{count}c_{8-hex}.json"""
    if not candles:
        elog.warn("No candles to save.")
        return None

    def fmt_dt(ts: int) -> str:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    random_suffix = ''.join(random.choices('0123456789abcdef', k=8))
    filename = f"{asset}_{timeframe_min}m_{target_count}c_{random_suffix}.json"
    filepath = CANDLES_DIR / filename

    meta = {
        "asset": asset,
        "timeframe_minutes": timeframe_min,
        "target_count": target_count,
        "actual_count": len(candles),
        "profit_percent": profit,
        "first_candle": fmt_dt(candles[0]['time']),
        "last_candle": fmt_dt(candles[-1]['time']),
        "first_candle_time": candles[0]['time'],
        "last_candle_time": candles[-1]['time'],
        "timezone": "UTC",
        "fetch_time": datetime.now().isoformat(timespec="seconds"),
        "fetch_timestamp": int(time.time()),
        "gap_filled_count": sum(1 for c in candles if c.get('volume', 1) == 0),
    }

    try:
        meta_txt = json.dumps(meta, indent=2, ensure_ascii=False).replace("\n", "\n  ")
        rows = []
        for c in candles:
            row = {
                "datetime": fmt_dt(c['time']),
                "time": c['time'],
                "open": c['open'],
                "high": c['high'],
                "low": c['low'],
                "close": c['close'],
                "volume": c.get('volume', 0),
            }
            rows.append("    " + json.dumps(row, ensure_ascii=False))
        body = ",\n".join(rows)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('{\n')
            f.write(f'  "metadata": {meta_txt},\n')
            f.write('  "candles": [\n')
            f.write(body + '\n')
            f.write('  ]\n}\n')
        return filepath
    except Exception as e:
        log_exception("save_candles_to_json", e)
        return None


# ============================================================================
# SECTION 15: INTERACTIVE HELPERS
# ============================================================================
async def _ainput(prompt: str) -> str:
    return await asyncio.to_thread(input, prompt)


async def prompt_credentials() -> Optional[Tuple[str, str]]:
    creds = load_credentials()
    if creds:
        elog.info(f"Found saved credentials for: {creds['email']}")
        use_saved = (await _ainput(
            f"{paint(C2.BRIGHT_YELLOW, 'Use saved credentials? (Y/n): ')}"
        )).strip().lower()
        if use_saved in ('y', '', 'yes'):
            return creds['email'], creds['password']
    print(paint(C2.BRIGHT_CYAN, 'Enter your Quotex credentials:'))
    email = (await _ainput(f"{paint(C2.BRIGHT_YELLOW, 'Email: ')}")).strip()
    password = (await _ainput(f"{paint(C2.BRIGHT_YELLOW, 'Password: ')}")).strip()
    if not email or not password:
        return None
    return email, password


async def prompt_timeframe() -> Optional[int]:
    while True:
        try:
            raw = (await _ainput(
                f"{paint(C2.BRIGHT_YELLOW, 'Timeframe in minutes (1, 5, 15, 30, 60) [default: 1]: ')}"
            )).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            return TIMEFRAME_DEFAULT
        if raw.lower() in ('exit', 'quit', 'q'):
            return None
        try:
            tf = int(raw)
            if tf <= 0:
                elog.error("Timeframe must be positive.")
                continue
            return tf
        except ValueError:
            elog.error("Please enter a valid integer.")


# ============================================================================
# SECTION 16: MAIN ASYNC ENTRY POINT
# ============================================================================
async def main_async():
    print_banner()
    purge_old_session()

    # Credentials
    creds = await prompt_credentials()
    if creds is None:
        elog.error("Invalid credentials.")
        return
    email, password = creds

    # Connect
    elog.info("Connecting to Quotex...")
    spinner = Spinner("Connecting to Quotex...")
    spinner.start()
    client = await connect_quotex(email, password, max_attempts=3)
    if client is None:
        spinner.stop("Connection failed after multiple attempts.", success=False)
        return
    spinner.stop("Connected successfully.")
    save_credentials(email, password)
    elog.success("Credentials saved.")

    # Wrap in ClientHolder
    holder = ClientHolder(client, email, password)

    # Install message interceptor
    interceptor = MessageInterceptor(client)
    if not interceptor.install():
        elog.error("Failed to install message interceptor.")
        return

    # Start never-sleep engine
    engine = NeverSleepEngine(holder, interceptor)
    engine.start()

    # Wait briefly for the WebSocket to settle
    await asyncio.sleep(1.5)

    # The 13 OTC pairs are hardcoded in OTC_ASSETS — no need to fetch the
    # instruments list. The MessageInterceptor will still CAPTURE profit %
    # automatically if the server pushes it (via keepalive's periodic
    # 42["instruments/get"] request), but we don't block on it.

    # Subscribe to live prices for all OTC pairs (the 13 hardcoded assets)
    live_sub = LivePriceSubscriber(interceptor)
    live_sub.subscribe_all(OTC_ASSETS, period=60)
    elog.success(f"Subscribed to live prices for {len(OTC_ASSETS)} OTC pairs")

    # Wait for live prices to arrive
    elog.info(f"Listening for live prices ({LIVE_PRICE_LISTEN_SECONDS}s)...")
    await asyncio.sleep(LIVE_PRICE_LISTEN_SECONDS)

    # Print summary table (profit % shows only if auto-pushed by server)
    InstrumentsFetcher(holder, interceptor).print_summary(OTC_ASSETS)

    # Ask for timeframe
    timeframe = await prompt_timeframe()
    if timeframe is None:
        await live_sub.unsubscribe_all()
        await engine.stop()
        try:
            await client.close()
        except Exception:
            pass
        return

    # Fetch candles for all 13 OTC pairs
    elog.info(f"Fetching {TARGET_CANDLE_COUNT} candles for each of {len(OTC_ASSETS)} OTC pairs (M{timeframe})...")
    fetcher = CandleFetcher(holder, interceptor)

    print(f"\n{paint_bold('  Starting batch fetch...', C2.BRIGHT_CYAN)}")
    print(hr(70, '═', C2.BRIGHT_BLUE))

    successes = 0
    failures = []
    try:
        for idx, asset in enumerate(OTC_ASSETS, 1):
            print(f"\n{paint_bold(f'  [{idx}/{len(OTC_ASSETS)}] {asset}', C2.BRIGHT_CYAN)}")
            print(hr(70, '─', C2.DIM))

            # Show live price + profit before fetch
            stats = interceptor.get_stats(asset)
            if stats['price'] is not None:
                price_str = paint_bold(f"{stats['price']}", C2.BRIGHT_GREEN)
                ticks_str = paint_dim(f"({stats['ticks_seen']} ticks)")
                print(f"  {paint('●', C2.BRIGHT_GREEN)} Live price: {price_str} {ticks_str}")
            else:
                print(f"  {paint('○', C2.BRIGHT_YELLOW)} No live ticks received — market may be closed")
            if stats['profit'] is not None:
                profit_str = paint_bold(f"{stats['profit']}%", C2.BRIGHT_GREEN)
                if stats['enabled']:
                    status_str = paint_bold('OPEN', C2.BRIGHT_GREEN)
                else:
                    status_str = paint_bold('CLOSED', C2.BRIGHT_RED)
                print(f"  {paint('💰', C2.DIM)} Profit: {profit_str}  Status: {status_str}")

            try:
                candles = await fetcher.fetch_exactly_n(asset, timeframe, TARGET_CANDLE_COUNT)
            except Exception as e:
                log_exception(f"fetch_{asset}", e)
                candles = []

            if candles:
                profit = interceptor.get_profit(asset)
                fp = save_candles_to_json(candles, asset, timeframe, TARGET_CANDLE_COUNT, profit)
                if fp:
                    elog.success(f"Saved {len(candles)} candles → {fp.name}")
                    successes += 1
                else:
                    failures.append(asset)
            else:
                failures.append(asset)

        # Final summary
        print(f"\n{hr(70, '═', C2.BRIGHT_BLUE)}")
        print(f"  {paint_bold('BATCH COMPLETE', C2.BRIGHT_WHITE)}")
        print(hr(70, '═', C2.BRIGHT_BLUE))
        print(f"  Successful: {paint_bold(f'{successes}/{len(OTC_ASSETS)}', C2.BRIGHT_GREEN)}")
        if failures:
            print(f"  Failed:     {paint_bold(f'{len(failures)}', C2.BRIGHT_RED)} — {', '.join(failures)}")
        print(f"  Output dir: {paint(str(CANDLES_DIR.absolute()), C2.BRIGHT_YELLOW)}")
        print(hr(70, '═', C2.BRIGHT_BLUE))

        # Print engine stats
        s = engine.stats()
        uptime = int(s['uptime_seconds'])
        print(f"\n  {paint_bold('Engine stats:', C2.BRIGHT_CYAN)}")
        print(f"    Uptime:        {int(uptime//3600):02d}:{int((uptime%3600)//60):02d}:{int(uptime%60):02d}")
        print(f"    Connection:    {paint_bold('ALIVE', C2.BRIGHT_GREEN) if s['connection_alive'] else paint_bold('DEAD', C2.BRIGHT_RED)}")
        print(f"    Drops:         {s['connection_drops']}")
        if s.get('last_drop_ago'):
            print(f"    Last drop:     {int(s['last_drop_ago'])}s ago")
        if s.get('last_ping_ago'):
            print(f"    Last ping:     {int(s['last_ping_ago'])}s ago")
        print(f"    Last message:  {int(s['last_message_ago'])}s ago")

    finally:
        # Cleanup
        await live_sub.unsubscribe_all()
        await engine.stop()
        interceptor.restore()
        try:
            await client.close()
        except Exception:
            pass
        print(f"\n{paint(C2.BRIGHT_CYAN, 'Done.')}")


# ============================================================================
# SECTION 17: MAIN ENTRY POINT
# ============================================================================
def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n{paint(C2.BRIGHT_YELLOW, 'Stopped.')}")
    except Exception as e:
        log_exception("main", e)
        traceback.print_exc()


if __name__ == "__main__":
    main()
