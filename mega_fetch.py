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

# ============================================================================
# SECTION 1: REUSE QUOTEX CORE FROM OTC_canda_.py
# ============================================================================
sys.path.insert(0, str(Path(__file__).parent))
from OTC_canda_ import (
    Quotex,
    connect_quotex,
    load_credentials,
    save_credentials,
    purge_old_session,
    logmsg,
    log_exception,
    Colors,
    CANDLES_DIR,
    CREDENTIALS_FILE,
)


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
LIVE_PRICE_LISTEN_SECONDS = 2.0    # how long to listen for ticks per asset
LIVE_PRICE_BROADCAST_INTERVAL = 0.5  # render interval for live price table

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
        """Capture binary frames + tick arrays; chain text to original."""
        # Binary frames: instruments/list or historical candles
        if isinstance(msg, (bytes, bytearray)):
            self._try_capture_binary(bytes(msg))
        else:
            text = msg if isinstance(msg, str) else msg.decode("utf-8", errors="ignore")
            # Detect instruments/list announcement
            if "_placeholder" in text and "instruments/list" in text:
                self._expecting_instruments_binary = True
                self._temp_status_instruments = text
            # Detect history/load announcement (response with binary attachment)
            elif "_placeholder" in text and ("history/list" in text or "history/load" in text):
                self._temp_status_history = text
            # Try to extract live ticks from text frames
            self._try_extract_ticks_from_text(text)

        # Chain to original handler
        if self._original_on_message is not None:
            try:
                self._original_on_message(wss, msg)
            except Exception:
                pass

    def _try_capture_binary(self, data: bytes) -> None:
        """Try to decode a binary frame as JSON (with 0x04 strip) or msgpack."""
        if len(data) < 128:
            return  # too small

        decoded = None
        decode_strategy = "none"

        # Strategy 1: strip 0x04, JSON
        candidate = data[1:] if len(data) > 0 and data[0] == 0x04 else data
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

        # Strategy 2: raw JSON
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

        # Strategy 3: msgpack fallback
        if decoded is None:
            try:
                import msgpack
                decoded = msgpack.unpackb(data, raw=False, strict_map_key=False)
                decode_strategy = "msgpack"
            except Exception:
                pass

        if decoded is None:
            return

        # Route the decoded payload
        # Case A: instruments/list (expected)
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
        if not isinstance(data, list) or len(data) < 5:
            return False
        sample = data[:5]
        for item in sample:
            if not isinstance(item, dict):
                return False
            if not any(k in item for k in ("asset", "id", "symbol", "name")):
                return False
        return True

    @staticmethod
    def _looks_like_history(data: Any) -> bool:
        if not isinstance(data, list) or len(data) < 1:
            return False
        # Each candle is either a dict {time, open, high, low, close}
        # or an array [time, open, close, high, low]
        first = data[0]
        if isinstance(first, dict) and 'time' in first:
            return True
        if isinstance(first, list) and len(first) >= 5:
            return True
        return False

    def _handle_instruments(self, data: Any, strategy: str, size: int) -> None:
        """Process the instruments list and extract profit % per asset."""
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
        for item in data:
            if not isinstance(item, dict):
                continue
            asset = item.get("asset") or item.get("id") or item.get("symbol")
            profit = item.get("profit") or item.get("payout")
            enabled = item.get("enabled") if "enabled" in item else item.get("open")
            if asset:
                if profit is not None:
                    self.profit_by_asset[asset] = int(profit)
                if enabled is not None:
                    self.enabled_by_asset[asset] = bool(enabled)

        elog.success(f"[instruments] captured via {strategy}: {len(data)} entries, "
                     f"{size:,} bytes, {len(self.profit_by_asset)} profit %")
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
        """Extract live price ticks from text frames like:
           42["quotes/stream",[[asset, time, price], ...]]
           42[<event>,[[asset, time, price], ...]]
        """
        if not text.startswith("42") or "[" not in text:
            return
        try:
            json_str = text[text.index("["):]
            parsed = json.loads(json_str)
            if not isinstance(parsed, list) or len(parsed) < 2:
                return
            payload = parsed[1] if len(parsed) == 2 else parsed
            self._extract_ticks(payload)
        except Exception:
            pass

    def _extract_ticks(self, payload: Any) -> None:
        """Look for tick arrays in the payload and record prices."""
        candidates = []
        if isinstance(payload, list):
            if payload and isinstance(payload[0], list):
                candidates = payload
            elif payload and isinstance(payload[0], str) and len(payload) >= 2:
                inner = payload[1]
                if isinstance(inner, list) and inner and isinstance(inner[0], list):
                    candidates = inner
        elif isinstance(payload, dict) and isinstance(payload.get("data"), list):
            candidates = payload["data"]

        for tick in candidates:
            if isinstance(tick, list) and len(tick) >= 3:
                asset = tick[0]
                price = tick[2]
                if isinstance(asset, str) and isinstance(price, (int, float)):
                    self.live_prices[asset] = float(price)
                    self.live_ticks_seen[asset] += 1
                    self.last_tick_at[asset] = time.time()

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
    """Fetches exactly N candles for an asset using overlapping chunks.

    Uses Quotex's get_historical_candles (which sends 42["history/load",...]
    internally and waits for the candles_ready event). Then deduplicates,
    fills gaps, and truncates/pads to exactly target_count.
    """

    def __init__(self, client_holder: ClientHolder, interceptor: MessageInterceptor):
        self.client_holder = client_holder
        self.interceptor = interceptor

    async def fetch_exactly_n(self, asset: str, timeframe_min: int,
                              target_count: int = TARGET_CANDLE_COUNT,
                              progress: bool = True) -> List[Dict]:
        """Fetch exactly target_count candles for asset."""
        period_seconds = int(timeframe_min * 60)
        display_name = f"{asset} (M{timeframe_min})"
        client = self.client_holder.client
        if client is None:
            elog.error(f"No client for {asset}")
            return []

        print(f"\n  {paint_bold('Fetching ', C2.BRIGHT_CYAN)}"
              f"{paint_bold(f'{target_count} candles', C2.BRIGHT_GREEN)} — {display_name}")

        now_ts = int(time.time())
        timeout = max(60, target_count * 5)
        candles_map: Dict[int, Dict] = {}
        fetch_start = time.time()

        chunk_offset = CHUNK_CANDLES * period_seconds
        step_offset = (CHUNK_CANDLES - OVERLAP_CANDLES) * period_seconds
        current_time = now_ts
        chunks_fetched = 0
        max_chunks = max(40, (target_count // (CHUNK_CANDLES - OVERLAP_CANDLES)) + 10)
        consecutive_empty = 0

        async def fetch_one(fetch_time: float) -> List[Dict]:
            aligned = int(fetch_time // period_seconds) * period_seconds
            try:
                candles = await asyncio.wait_for(
                    client.get_historical_candles(
                        asset,
                        amount_of_seconds=chunk_offset,
                        period=period_seconds,
                        max_workers=3,
                        progress_callback=None,
                    ),
                    timeout=timeout,
                )
                return candles or []
            except Exception as e:
                elog.debug(f"chunk fetch error at {int(fetch_time)}: {e}")
                return []

        while len(candles_map) < target_count and chunks_fetched < max_chunks:
            batch_times = []
            t = current_time
            for _ in range(FETCH_BATCH_SIZE):
                batch_times.append(t)
                t -= step_offset

            results = await asyncio.gather(*[fetch_one(t) for t in batch_times])
            chunks_fetched += FETCH_BATCH_SIZE

            has_new = False
            batch_oldest = current_time
            for raw in results:
                if not raw:
                    continue
                for c in raw:
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
                            has_new = True
                            if aligned < batch_oldest:
                                batch_oldest = aligned
                    except Exception:
                        continue

            if not has_new:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    elog.warn(f"Reached end of available data for {asset}.")
                    break
            else:
                consecutive_empty = 0
                current_time = batch_oldest - (OVERLAP_CANDLES * period_seconds)

            if progress:
                elapsed = time.time() - fetch_start
                pct = min(len(candles_map) / target_count, 1.0)
                bar_len = 30
                filled = int(bar_len * pct)
                bar = paint(C2.BRIGHT_GREEN, '█' * filled) + paint(C2.DIM, '░' * (bar_len - filled))
                sys.stdout.write(
                    f"\r  {paint('[', C2.DIM)}{bar}{paint(']', C2.DIM)} "
                    f"{pct*100:5.1f}% | "
                    f"{paint_bold(f'{len(candles_map)}', C2.BRIGHT_GREEN)}/{target_count} | "
                    f"{int(elapsed):>3}s   "
                )
                sys.stdout.flush()

        if progress:
            print()

        if not candles_map:
            elog.error(f"No candles fetched for {asset}.")
            return []

        # Sort by time
        candles = sorted(candles_map.values(), key=lambda x: x['time'])

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

    # Fetch instruments list (profit %)
    elog.info("Fetching instruments list (for profit %)...")
    instruments = InstrumentsFetcher(holder, interceptor)
    instruments_ok = await instruments.fetch(timeout=30.0)

    # Subscribe to live prices for all OTC pairs
    live_sub = LivePriceSubscriber(interceptor)
    live_sub.subscribe_all(OTC_ASSETS, period=60)
    elog.success(f"Subscribed to live prices for {len(OTC_ASSETS)} assets")

    # Wait for live prices to arrive
    elog.info(f"Listening for live prices ({LIVE_PRICE_LISTEN_SECONDS}s)...")
    await asyncio.sleep(LIVE_PRICE_LISTEN_SECONDS)

    # Print instruments summary (profit % + live price)
    if instruments_ok:
        instruments.print_summary(OTC_ASSETS)
    else:
        elog.warn("Could not fetch instruments list. Continuing without profit %.")

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
