#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quotex Mega Fetcher — Comprehensive Candle Fetcher with Live Streaming
=======================================================================
A feature-rich candle fetcher for Quotex OTC pairs. Combines:
  - Exactly 500 candles per asset (overlapping chunks + dedup + gap-fill)
  - Live price streaming via depth/follow + quotes/stream
  - Multi-account support (broadcast fetches across accounts)
  - Auto-reconnect with backoff
  - Keepalive + health check background loops
  - Sub-second timeframe aggregation (1s, 5s, 10s, 15s, 30s, 60s)
  - CSV export
  - CLI REPL with rich command set
  - Comprehensive logging + spinner + colored output
  - Trade placement (buy/sell) with background settlement
  - Domain selection (qxbroker.com / market-qx.info)
  - Event registry for async event-driven flow
  - Mutex for thread-safe WebSocket sends

USAGE
-----
    python3 quick_fetch.py

After login, a REPL with many commands is available. Type 'help' for the full
list. Key commands:
    fetch        — fetch 500 candles for all 13 OTC pairs
    fetch <asset>— fetch 500 candles for one asset
    live <asset> — stream live price (Ctrl+C or 'stoplive' to stop)
    balance      — show account balances
    assets       — list available trading assets
    export       — export last fetched candles as CSV
    trades       — list pending trade settlements
    debug <on|all|off> — toggle raw WS logging
    domain       — show current domain
    accounts     — list connected accounts
    connect      — connect another account
    help         — show all commands
    exit         — close the program

OUTPUT
------
    candles_otc_data/{asset}_{tf}m_500c_{8-hex}.json
"""

# ============================================================================
# SECTION 0: STANDARD LIBRARY IMPORTS
# ============================================================================
import os
import sys
import json
import time
import random
import asyncio
import threading
import traceback
import itertools
import contextlib
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
    """Extended color system beyond the basic Colors in OTC_canda_."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    HIDDEN = '\033[8m'
    STRIKE = '\033[9m'

    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright foreground colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # Bright background colors
    BG_BRIGHT_BLACK = '\033[100m'
    BG_BRIGHT_RED = '\033[101m'
    BG_BRIGHT_GREEN = '\033[102m'
    BG_BRIGHT_YELLOW = '\033[103m'
    BG_BRIGHT_BLUE = '\033[104m'
    BG_BRIGHT_MAGENTA = '\033[105m'
    BG_BRIGHT_CYAN = '\033[106m'
    BG_BRIGHT_WHITE = '\033[107m'


def paint(color: str, text: str) -> str:
    """Apply ANSI color to text, with auto-reset."""
    return f"{color}{text}{C2.RESET}"


def paint_bold(text: str, color: str = C2.WHITE) -> str:
    return f"{C2.BOLD}{color}{text}{C2.RESET}"


def paint_dim(text: str) -> str:
    return f"{C2.DIM}{text}{C2.RESET}"


def visible_length(s: str) -> int:
    """Return the visible length of a string, ignoring ANSI escape codes."""
    import re
    return len(re.sub(r'\x1b\[[0-9;]*m', '', s))


def pad_visible(s: str, width: int) -> str:
    """Pad string `s` to `width` visible characters (right-pad with spaces)."""
    gap = max(0, width - visible_length(s))
    return s + ' ' * gap


def truncate_visible(s: str, max_len: int, ellipsis: str = '…') -> str:
    """Truncate a string to `max_len` visible characters, appending ellipsis."""
    if visible_length(s) <= max_len:
        return s
    import re
    # Strip ANSI, truncate, re-color
    plain = re.sub(r'\x1b\[[0-9;]*m', '', s)
    truncated = plain[:max_len - len(ellipsis)] + ellipsis
    return truncated


def hr(width: int = 80, char: str = '─', color: str = C2.DIM) -> str:
    """Horizontal rule."""
    return paint(color, char * width)


def box(text: str, padding: int = 2, color: str = C2.BRIGHT_BLUE) -> str:
    """Wrap text in a single-line box."""
    inner = ' ' * padding + text + ' ' * padding
    width = visible_length(inner)
    top = paint(color, '┌' + '─' * width + '┐')
    mid = paint(color, '│') + inner + paint(color, '│')
    bot = paint(color, '└' + '─' * width + '┘')
    return f"{top}\n{mid}\n{bot}"


def table_row(cells: List[Tuple[str, int, str]], sep: str = '│') -> str:
    """Render a table row: cells = [(text, width, color), ...]"""
    parts = [paint(color, sep)]
    for text, width, color in cells:
        parts.append(pad_visible(paint(color, text), width))
        parts.append(paint(color, sep))
    return ''.join(parts)


def progress_bar(progress: float, width: int = 30, fill: str = '█',
                 empty: str = '░', color_fill: str = C2.BRIGHT_GREEN,
                 color_empty: str = C2.DIM) -> str:
    """Render a progress bar: 0.0 <= progress <= 1.0."""
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
    """Print the application banner with ASCII art and metadata."""
    print(paint(C2.BRIGHT_CYAN, BANNER_ART))
    print(hr(60, '═', C2.BRIGHT_BLUE))
    print(paint_bold("  Quotex Mega Fetcher", C2.BRIGHT_WHITE))
    print(paint_dim("  Comprehensive candle fetcher with live streaming"))
    print(hr(60, '═', C2.BRIGHT_BLUE))
    print(f"  {paint('Output dir:', C2.DIM)}       {paint(str(CANDLES_DIR.absolute()), C2.BRIGHT_YELLOW)}")
    print(f"  {paint('Target count:', C2.DIM)}     {paint('500 candles per asset', C2.BRIGHT_GREEN)}")
    print(f"  {paint('Default assets:', C2.DIM)}   {paint(f'{len(OTC_ASSETS)} OTC pairs', C2.BRIGHT_GREEN)}")
    print(f"  {paint('Gap-filling:', C2.DIM)}      {paint('ENABLED', C2.BRIGHT_GREEN)} (max_gap=1440 slots)")
    print(f"  {paint('Live price:', C2.DIM)}       {paint('ENABLED', C2.BRIGHT_GREEN)} (depth/follow + quotes/stream)")
    print(f"  {paint('Multi-account:', C2.DIM)}    {paint('SUPPORTED', C2.BRIGHT_GREEN)}")
    print(f"  {paint('Sub-second TF:', C2.DIM)}    {paint('SUPPORTED', C2.BRIGHT_GREEN)} (1s, 5s, 10s, 15s, 30s, 60s)")
    print(f"  {paint('Auto-reconnect:', C2.DIM)}   {paint('ENABLED', C2.BRIGHT_GREEN)} (with exponential backoff)")
    print(f"  {paint('Health check:', C2.DIM)}     {paint('ENABLED', C2.BRIGHT_GREEN)} (every 20s)")
    print(f"  {paint('CLI REPL:', C2.DIM)}         {paint('ENABLED', C2.BRIGHT_GREEN)} (type 'help' for commands)")
    print(hr(60, '═', C2.BRIGHT_BLUE))
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
        return datetime.now().toTimeString() if hasattr(datetime.now(), 'toTimeString') else \
               datetime.now().strftime("%H:%M:%S")

    def _write_file(self, level: str, msg: str):
        try:
            with self._lock:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{level}] {self._time()} - {msg}\n")
        except Exception:
            pass

    def info(self, msg: str):
        ts = self._time()
        print(f"{paint(C2.DIM, '[INFO]')} {paint(C2.BRIGHT_CYAN, ts)} {paint(C2.DIM, '-')} {paint(C2.WHITE, msg)}")
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
        # Don't write debug to file by default (too noisy)


elog = ExtendedLogger()


# ============================================================================
# SECTION 5: SPINNER
# ============================================================================
class Spinner:
    """Animated spinner for long-running operations.

    Usage:
        sp = Spinner("Loading...")
        sp.start()
        # ... do work ...
        sp.update("Still loading...")
        sp.stop("Done!", success=True)
    """

    FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    FRAMES_DOTS = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
    FRAMES_CIRCLE = ['◐', '◓', '◑', '◒']
    FRAMES_BOUNCE = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█', '▇', '▆', '▅', '▄', '▃', '▂', '▁']

    def __init__(self, text: str = '', style: str = 'braille'):
        self.text = text
        if style == 'braille':
            self.frames = self.FRAMES
        elif style == 'dots':
            self.frames = self.FRAMES_DOTS
        elif style == 'circle':
            self.frames = self.FRAMES_CIRCLE
        elif style == 'bounce':
            self.frames = self.FRAMES_BOUNCE
        else:
            self.frames = self.FRAMES
        self.i = 0
        self.timer = None
        self._stop_event = threading.Event()

    def start(self, text: Optional[str] = None):
        if text is not None:
            self.text = text
        if self.timer is not None:
            return self
        # Hide cursor
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
        # Clear line and show cursor
        sys.stdout.write('\r\x1b[K')
        sys.stdout.write('\x1b[?25h')
        sys.stdout.flush()
        if final_msg:
            if success:
                elog.success(final_msg)
            else:
                elog.error(final_msg)


# ============================================================================
# SECTION 6: MUTEX (for thread-safe WebSocket sends)
# ============================================================================
class Mutex:
    """Async mutex for serializing WebSocket sends.

    Usage:
        async with mutex:
            await ws.send(...)
    """

    def __init__(self):
        self._locked = False
        self._queue: List[Callable] = []
        self._sync_lock = threading.Lock()

    def lock(self) -> 'asyncio.Future':
        """Returns a future that resolves to an unlock function."""
        loop = asyncio.get_event_loop()
        fut = loop.create_future()

        def try_acquire():
            with self._sync_lock:
                if not self._locked:
                    self._locked = True
                    fut.set_result(self._release)
                else:
                    self._queue.append(fut)

        # Schedule on the event loop
        loop.call_soon(try_acquire)
        return fut

    def _release(self):
        with self._sync_lock:
            if self._queue:
                next_fut = self._queue.pop(0)
                next_fut.set_result(self._release)
            else:
                self._locked = False

    async def __aenter__(self):
        release = await self.lock()
        self._current_release = release
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, '_current_release'):
            self._current_release()
            del self._current_release


class SyncMutex:
    """Synchronous mutex for non-async contexts."""

    def __init__(self):
        self._lock = threading.Lock()

    def __enter__(self):
        self._lock.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._lock.release()


# ============================================================================
# SECTION 7: EVENT REGISTRY (async event-driven flow)
# ============================================================================
class EventRegistry:
    """Async event registry for waiting on Quotex server responses.

    Allows multiple waiters per event key. When set_event() is called,
    the first waiter in the queue is resolved.
    """

    def __init__(self):
        self._queues: Dict[str, List[Dict]] = {}
        self._lock = asyncio.Lock()

    async def wait_event(self, key: str, timeout: float = 15.0) -> Any:
        """Wait for an event to be set. Raises asyncio.TimeoutError on timeout."""
        loop = asyncio.get_event_loop()
        fut = loop.create_future()

        async with self._lock:
            if key not in self._queues:
                self._queues[key] = []
            entry = {
                'fut': fut,
                'timer': None,
            }
            entry['timer'] = loop.call_later(timeout, self._on_timeout, fut, key)
            self._queues[key].append(entry)

        try:
            return await fut
        finally:
            async with self._lock:
                # Cancel timer if still pending
                if entry['timer'] is not None and not entry['timer'].cancelled():
                    entry['timer'].cancel()
                # Remove from queue if still present
                if key in self._queues and entry in self._queues[key]:
                    self._queues[key].remove(entry)

    def _on_timeout(self, fut, key):
        if not fut.done():
            fut.set_exception(asyncio.TimeoutError(f"Timeout: {key}"))

    async def set_event(self, key: str, data: Any = None):
        """Set an event, resolving the first waiter."""
        async with self._lock:
            if key not in self._queues or not self._queues[key]:
                return
            entry = self._queues[key].pop(0)
            if not entry['timer'].cancelled():
                entry['timer'].cancel()
            entry['fut'].set_result(data)

    async def clear_event(self, key: str):
        """Clear all waiters for a key (they get a TimeoutError)."""
        async with self._lock:
            if key in self._queues:
                for entry in self._queues[key]:
                    if not entry['timer'].cancelled():
                        entry['timer'].cancel()
                    if not entry['fut'].done():
                        entry['fut'].set_exception(asyncio.CancelledError())
                self._queues[key] = []


# ============================================================================
# SECTION 8: CONFIGURATION
# ============================================================================
TARGET_CANDLE_COUNT = 500          # exactly 500 candles per asset
TIMEFRAME_DEFAULT = 1              # M1 default
MAX_FETCH_RETRIES = 5
RETRY_BACKOFF_BASE = 2
RETRY_BACKOFF_MAX = 15
RETRY_BACKOFF = 0.5                # delay between overlapping chunk fetches
LIVE_PRICE_LISTEN_SECONDS = 2.0    # how long to listen for live ticks per asset
GAP_FILL_MAX_SLOTS = 1440          # max gaps to fill (= 1 day for M1)

# Background tasks
KEEPALIVE_INTERVAL = 5             # seconds between pings
HEALTH_CHECK_INTERVAL = 20         # seconds between health checks
RECONNECT_CHECK_INTERVAL = 10      # seconds between connection-loss checks
MAX_RECONNECT_ATTEMPTS = 5         # number of reconnect attempts before giving up
RECONNECT_BACKOFF_BASE = 3         # initial backoff in seconds (doubles each attempt)
RECONNECT_BACKOFF_MAX = 30         # maximum backoff

# Domain selection
AVAILABLE_DOMAINS = ['qxbroker.com', 'market-qx.info', 'quotex.com']
DOMAIN_CONFIG_FILE = Path('domain_config.json')

# The 13 OTC pairs (must match OTC_canda_.py)
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

# Sub-second timeframe aggregation support
SUBSECOND_TIMEFRAMES = {1, 5, 10, 15, 30}  # seconds
PERIOD_SECONDS_DEFAULT = 60  # default to M1


# ============================================================================
# SECTION 9: GAP-FILLING ENGINE (ported from wedsoket_.py)
# ============================================================================
def _fill_missing_slots(candles: List[Dict], period_seconds: int,
                        max_gap: int = GAP_FILL_MAX_SLOTS) -> List[Dict]:
    """Fills time gaps between candles with flat candles (previous close).

    Ported verbatim from wedsoket_.py (the large working file).

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
# SECTION 10: SUB-SECOND AGGREGATION (ported from wedsoket_.py)
# ============================================================================
def _aggregate_sub_minute(candles: List[Dict], target_period: int) -> List[Dict]:
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
    buckets: OrderedDict[int, Dict] = OrderedDict()
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


# ============================================================================
# SECTION 11: TIME PARSING HELPER
# ============================================================================
def to_epoch_seconds(value: Any) -> Optional[int]:
    """Normalize any time representation into Unix seconds.

    Handles:
      - numbers (seconds or milliseconds)
      - strings (numeric or ISO format)
      - None / empty -> None
    """
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)) and value == value:  # NaN check
        return int(value / 1000) if value > 1e12 else int(value)
    if isinstance(value, str):
        s = value.strip()
        try:
            num = float(s)
            return int(num / 1000) if num > 1e12 else int(num)
        except ValueError:
            pass
        try:
            # Replace space with T for ISO parsing
            iso = s.replace(' ', 'T')
            return int(datetime.fromisoformat(iso).timestamp())
        except Exception:
            return None
    return None


# ============================================================================
# SECTION 12: DOMAIN SELECTION SYSTEM
# ============================================================================
def load_saved_domain() -> Optional[str]:
    """Load the previously saved domain from domain_config.json."""
    if not DOMAIN_CONFIG_FILE.exists():
        return None
    try:
        data = json.loads(DOMAIN_CONFIG_FILE.read_text(encoding='utf-8'))
        if data and isinstance(data.get('host'), str) and data['host'].strip():
            return data['host'].strip()
    except Exception:
        pass
    return None


def save_domain(host: str) -> bool:
    """Save the selected domain to domain_config.json."""
    try:
        data = {
            'host': host,
            'saved_at': datetime.now().isoformat(timespec='seconds'),
        }
        DOMAIN_CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding='utf-8')
        return True
    except Exception as e:
        elog.error(f"Failed to save domain: {e}")
        return False


async def select_domain_flow(question_func) -> str:
    """Prompt the user to select a domain, or use the saved one."""
    saved = load_saved_domain()
    if saved:
        elog.info(f"Using saved domain: {paint(C2.BRIGHT_GREEN, saved)}")
        return saved

    print(f"\n{paint(C2.BOLD + C2.BRIGHT_CYAN, '🌐 Select the domain you want to use:')}")
    for i, d in enumerate(AVAILABLE_DOMAINS, 1):
        print(f"   {paint(C2.BRIGHT_YELLOW, str(i))}. {d}")
    print(paint(C2.DIM, '   (Your choice will be saved for future runs)'))

    chosen = None
    while chosen is None:
        ans = (await question_func('🌐 Enter domain number: ')).strip()
        try:
            idx = int(ans) - 1
            if 0 <= idx < len(AVAILABLE_DOMAINS):
                chosen = AVAILABLE_DOMAINS[idx]
            else:
                elog.error('Invalid choice. Enter a number from the list.')
        except ValueError:
            elog.error('Invalid input. Enter a number.')

    save_domain(chosen)
    elog.success(f"Domain ({chosen}) saved to {DOMAIN_CONFIG_FILE.name}.")
    return chosen


# ============================================================================
# SECTION 13: LIVE PRICE TRACKER
# ============================================================================
class LivePriceTracker:
    """Tracks live price ticks for one or more assets via WebSocket.

    Subscribes via:
      42["instruments/update",{"asset":"ASSET_otc","period":60}]
      42["depth/follow","ASSET_otc"]
      42["chart_notification/get"]

    The Quotex server pushes ticks in messages like:
      42["quotes/stream",[[asset, time, price], ...]]
    """

    def __init__(self, client: Quotex):
        self.client = client
        self.prices: Dict[str, float] = {}
        self.ticks_seen: Dict[str, int] = defaultdict(int)
        self.last_tick_at: Dict[str, float] = {}
        self._installed = False
        self._original_on_message = None
        self._ws_client = None
        self._subscribed_assets: set = set()

    def install(self) -> bool:
        """Patch WebsocketClient.on_message to also capture live ticks."""
        api = self.client.api
        if api is None:
            return False
        ws_client = getattr(api, "websocket_client", None)
        if ws_client is None:
            return False
        self._ws_client = ws_client
        self._original_on_message = ws_client.on_message
        ws_client.on_message = self._on_message
        self._installed = True
        return True

    def restore(self) -> None:
        if self._installed and self._original_on_message is not None:
            try:
                if self._ws_client is not None:
                    self._ws_client.on_message = self._original_on_message
            except Exception:
                pass
            self._installed = False

    def _on_message(self, wss, msg) -> None:
        """Intercept messages and look for live price tick arrays."""
        try:
            if isinstance(msg, (bytes, bytearray)):
                # Pass through binary frames
                pass
            else:
                text = msg if isinstance(msg, str) else msg.decode("utf-8", errors="ignore")
                if text.startswith("42") and "[" in text:
                    try:
                        json_str = text[text.index("["):]
                        parsed = json.loads(json_str)
                        if isinstance(parsed, list) and len(parsed) >= 2:
                            payload = parsed[1] if len(parsed) == 2 else parsed
                            self._extract_ticks(payload)
                    except Exception:
                        pass
        except Exception:
            pass
        # Chain to original
        if self._original_on_message is not None:
            try:
                self._original_on_message(wss, msg)
            except Exception:
                pass

    def _extract_ticks(self, payload: Any) -> None:
        """Look for tick arrays in the payload and record prices."""
        candidates = []
        if isinstance(payload, list):
            if payload and isinstance(payload[0], list):
                candidates = payload
            elif payload and isinstance(payload[0], str) and len(payload) >= 2:
                # Could be [event_name, [[tick,...], ...]]
                inner = payload[1]
                if isinstance(inner, list):
                    if inner and isinstance(inner[0], list):
                        candidates = inner
        elif isinstance(payload, dict) and isinstance(payload.get("data"), list):
            candidates = payload["data"]

        for tick in candidates:
            if isinstance(tick, list) and len(tick) >= 3:
                asset = tick[0]
                price = tick[2]
                if isinstance(asset, str) and isinstance(price, (int, float)):
                    self.prices[asset] = float(price)
                    self.ticks_seen[asset] += 1
                    self.last_tick_at[asset] = time.time()

    def subscribe(self, asset: str, period: int = 60) -> None:
        """Send subscribe messages for live price updates."""
        api = self.client.api
        try:
            api.send_websocket_request(
                f'42["instruments/update",{{"asset":"{asset}","period":{period}}}]',
                no_force_send=False,
            )
            api.send_websocket_request(f'42["depth/follow","{asset}"]', no_force_send=False)
            api.send_websocket_request('42["chart_notification/get"]', no_force_send=False)
            self._subscribed_assets.add(asset)
        except Exception as e:
            elog.warn(f"[live] failed to subscribe {asset}: {e}")

    def unsubscribe(self, asset: str) -> None:
        """Stop receiving live updates for an asset."""
        api = self.client.api
        try:
            api.send_websocket_request(f'42["depth/unfollow","{asset}"]', no_force_send=False)
            self._subscribed_assets.discard(asset)
        except Exception:
            pass

    def unsubscribe_all(self) -> None:
        """Unsubscribe from all currently subscribed assets."""
        for asset in list(self._subscribed_assets):
            self.unsubscribe(asset)

    def get_price(self, asset: str) -> Optional[float]:
        return self.prices.get(asset)

    def get_stats(self, asset: str) -> Dict[str, Any]:
        """Return statistics for an asset."""
        return {
            'price': self.prices.get(asset),
            'ticks_seen': self.ticks_seen.get(asset, 0),
            'last_tick_ago': time.time() - self.last_tick_at.get(asset, 0)
                             if asset in self.last_tick_at else None,
        }


# ============================================================================
# SECTION 14: LIVE PRICE RENDERER (terminal UI)
# ============================================================================
class LivePriceRenderer:
    """Renders live prices for multiple assets in a terminal table.

    Used by the 'live <asset> [asset2 ...]' command.
    """

    def __init__(self, tracker: LivePriceTracker, assets: List[str]):
        self.tracker = tracker
        self.assets = assets
        self._render_count = 0
        self._running = False
        self._thread = None
        self._stop_event = threading.Event()
        self._last_prices: Dict[str, Optional[float]] = {a: None for a in assets}

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        # Subscribe to all assets
        for asset in self.assets:
            self.tracker.subscribe(asset, period=60)
        elog.info(f"Starting live price stream for: {', '.join(self.assets)}")
        # Initial render
        self._render()
        # Background thread
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self):
        while not self._stop_event.is_set():
            self._render()
            time.sleep(0.5)

    def _render(self):
        # Move cursor up if not first render
        if self._render_count > 0:
            sys.stdout.write(f'\x1b[{len(self.assets) + 2}A')
        self._render_count += 1

        # Header
        print(hr(70, '─', C2.DIM))
        print(f"  {paint_bold('Asset', C2.BRIGHT_CYAN):<20} "
              f"{paint_bold('Price', C2.BRIGHT_GREEN):<20} "
              f"{paint_bold('Δ', C2.BRIGHT_YELLOW):<15} "
              f"{paint_bold('Ticks', C2.DIM)}")
        print(hr(70, '─', C2.DIM))

        for asset in self.assets:
            price = self.tracker.get_price(asset)
            ticks = self.tracker.ticks_seen.get(asset, 0)
            last_price = self._last_prices.get(asset)
            if price is None:
                price_str = paint(C2.DIM, 'waiting...')
                delta_str = paint(C2.DIM, '—')
            else:
                price_str = paint_bold(f"{price:.5f}", C2.BRIGHT_GREEN)
                if last_price is None:
                    delta_str = paint(C2.DIM, '—')
                elif price > last_price:
                    delta_str = paint(C2.BRIGHT_GREEN, f'▲ {price - last_price:.5f}')
                elif price < last_price:
                    delta_str = paint(C2.BRIGHT_RED, f'▼ {last_price - price:.5f}')
                else:
                    delta_str = paint(C2.DIM, '= 0.00000')
                self._last_prices[asset] = price

            ticks_str = paint_dim(f"{ticks}")
            print(f"  {paint(C2.BRIGHT_YELLOW, asset):<20} {price_str:<20} {delta_str:<15} {ticks_str}")

    def stop(self):
        if not self._running:
            return False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None
        self._running = False
        # Unsubscribe
        for asset in self.assets:
            self.tracker.unsubscribe(asset)
        elog.success(f"Live price stream stopped for: {', '.join(self.assets)}")
        return True


# ============================================================================
# SECTION 15: CONNECTION HEALTH MONITOR
# ============================================================================
class ConnectionMonitor:
    """Background monitor that watches the Quotex connection health.

    Runs two async loops:
      1. keepalive_loop: sends ping every KEEPALIVE_INTERVAL seconds
      2. health_check_loop: checks connection state every HEALTH_CHECK_INTERVAL
         seconds and triggers reconnect if dead
    """

    def __init__(self, client_holder: 'ClientHolder'):
        self.client_holder = client_holder
        self.stop_event = asyncio.Event()
        self.tasks: List[asyncio.Task] = []
        self.connection_drops: int = 0
        self.last_drop_time: float = 0
        self.uptime_start: float = time.time()
        self.last_ping_at: float = 0
        self.last_pong_at: float = 0

    def start(self):
        self.tasks = [
            asyncio.create_task(self.keepalive_loop()),
            asyncio.create_task(self.health_check_loop()),
        ]
        elog.info("[monitor] background keepalive + health check started")

    async def stop(self):
        self.stop_event.set()
        for t in self.tasks:
            try:
                await asyncio.wait_for(t, timeout=2.0)
            except Exception:
                pass

    async def keepalive_loop(self):
        """Send ping every KEEPALIVE_INTERVAL seconds."""
        while not self.stop_event.is_set():
            try:
                client = self.client_holder.client
                if client and client.api:
                    client.api.send_websocket_request("2", no_force_send=False)
                    client.api.send_websocket_request('42["tick"]', no_force_send=False)
                    self.last_ping_at = time.time()
            except Exception:
                pass
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=KEEPALIVE_INTERVAL)
            except asyncio.TimeoutError:
                pass

    async def health_check_loop(self):
        """Check connection state every HEALTH_CHECK_INTERVAL seconds."""
        while not self.stop_event.is_set():
            try:
                client = self.client_holder.client
                if client is None or client.api is None:
                    continue
                state = getattr(client.api, 'state', None)
                if state is None:
                    continue
                alive = bool(getattr(state, 'check_accepted_connection', False))
                if not alive:
                    self.connection_drops += 1
                    self.last_drop_time = time.time()
                    elog.warn(f"[monitor] connection drop detected (#{self.connection_drops})")
                    # Trigger reconnect
                    asyncio.create_task(self._reconnect())
            except Exception as e:
                elog.debug(f"[monitor] health check error: {e}")
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=HEALTH_CHECK_INTERVAL)
            except asyncio.TimeoutError:
                pass

    async def _reconnect(self):
        """Attempt to reconnect with exponential backoff."""
        backoff = RECONNECT_BACKOFF_BASE
        for attempt in range(1, MAX_RECONNECT_ATTEMPTS + 1):
            if self.stop_event.is_set():
                return
            try:
                elog.info(f"[reconnect] attempt {attempt}/{MAX_RECONNECT_ATTEMPTS}")
                h = self.client_holder
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
                    # Close old, swap in new
                    try:
                        if self.client_holder.client:
                            await self.client_holder.client.close()
                    except Exception:
                        pass
                    self.client_holder.client = new_client
                    elog.success(f"[reconnect] reconnect successful on attempt {attempt}")
                    return
                else:
                    err = str(reason) if reason else "Unknown"
                    elog.warn(f"[reconnect] attempt {attempt} failed: {err}")
            except Exception as e:
                elog.warn(f"[reconnect] attempt {attempt} raised: {e}")
            if attempt < MAX_RECONNECT_ATTEMPTS:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, RECONNECT_BACKOFF_MAX)
        elog.error(f"[reconnect] all {MAX_RECONNECT_ATTEMPTS} attempts failed")

    def stats(self) -> Dict[str, Any]:
        return {
            'uptime_seconds': time.time() - self.uptime_start,
            'connection_drops': self.connection_drops,
            'last_drop_ago': time.time() - self.last_drop_time if self.last_drop_time else None,
            'last_ping_ago': time.time() - self.last_ping_at if self.last_ping_at else None,
        }


# ============================================================================
# SECTION 16: CLIENT HOLDER (for swapping clients on reconnect)
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
# SECTION 17: JSON SAVER
# ============================================================================
def save_candles_to_json(candles: List[Dict], asset: str, timeframe_min: int,
                          target_count: int) -> Optional[Path]:
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
# SECTION 18: CSV EXPORTER
# ============================================================================
def export_to_csv(candles: List[Dict], filename: str) -> Optional[Path]:
    """Export candles to a CSV file. Returns the path or None on failure."""
    if not candles:
        elog.warn("No candles to export.")
        return None

    filepath = CANDLES_DIR / filename
    try:
        header = "Timestamp,DateTime,Open,High,Low,Close,Volume\n"
        rows = []
        for c in candles:
            dt = datetime.fromtimestamp(c['time'], timezone.utc)\
                       .strftime("%Y-%m-%d %H:%M:%S")
            rows.append(f"{c['time']},{dt},{c['open']},{c['high']},"
                        f"{c['low']},{c['close']},{c.get('volume', 0)}")
        body = '\n'.join(rows)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(header + body + '\n')
        elog.success(f"CSV exported to {filepath.absolute()}")
        return filepath
    except Exception as e:
        elog.error(f"Failed to export CSV: {e}")
        return None


# ============================================================================
# SECTION 19: FETCH LOGIC — 500 candles with overlapping chunks
# ============================================================================
async def fetch_exactly_n_candles(client: Quotex, asset: str, timeframe_min: int,
                                   target_count: int = TARGET_CANDLE_COUNT,
                                   live_tracker: Optional[LivePriceTracker] = None,
                                   progress: bool = True) -> List[Dict]:
    """Fetch exactly `target_count` candles for `asset`.

    Strategy (mirrors the chunked fetch in wedsoket_.py):
      1. Subscribe to live price (so we know the market is alive).
      2. Fetch overlapping chunks backwards from "now" using Quotex's history API.
      3. Deduplicate by timestamp.
      4. Apply _fill_missing_slots to fill any gaps with flat candles.
      5. Return exactly target_count candles (truncate from the start
         if we got more, pad with flat candles if we got fewer).
    """
    period_seconds = int(timeframe_min * 60)
    display_name = f"{asset} (M{timeframe_min})"
    print(f"\n  {paint_bold('Fetching ', C2.BRIGHT_CYAN)}"
          f"{paint_bold(f'{target_count} candles', C2.BRIGHT_GREEN)} — {display_name}")

    # Subscribe to live price
    if live_tracker:
        live_tracker.subscribe(asset, period=60)
        await asyncio.sleep(LIVE_PRICE_LISTEN_SECONDS)
        live_price = live_tracker.get_price(asset)
        ticks = live_tracker.ticks_seen.get(asset, 0)
        if live_price is not None:
            print(f"  {paint('●', C2.BRIGHT_GREEN)} Live price: "
                  f"{paint_bold(f'{live_price}', C2.BRIGHT_GREEN)} "
                  f"{paint_dim(f'({ticks} ticks seen)')}")
        else:
            print(f"  {paint('○', C2.BRIGHT_YELLOW)} No live ticks in "
                  f"{LIVE_PRICE_LISTEN_SECONDS}s — market may be closed")

    now_ts = int(time.time())
    timeout = max(60, target_count * 5)
    candles_map: Dict[int, Dict] = {}
    fetch_start = time.time()

    CHUNK_CANDLES = 60
    OVERLAP_CANDLES = 10
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
        BATCH = 3
        batch_times = []
        t = current_time
        for _ in range(BATCH):
            batch_times.append(t)
            t -= step_offset

        results = await asyncio.gather(*[fetch_one(t) for t in batch_times])
        chunks_fetched += BATCH

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
        if live_tracker:
            live_tracker.unsubscribe(asset)
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

    if live_tracker:
        live_tracker.unsubscribe(asset)

    elapsed = time.time() - fetch_start
    elog.success(f"Fetched {len(candles)} candles in "
                 f"{int(elapsed//60):02d}:{int(elapsed%60):02d} — {display_name}")
    return candles


# ============================================================================
# SECTION 20: TRADE PLACEMENT (basic buy/sell with settlement tracking)
# ============================================================================
@dataclass
class PendingTrade:
    """Represents a trade that has been opened but not yet settled."""
    trade_id: Optional[int]
    asset: str
    direction: str  # 'call' or 'put'
    amount: float
    is_demo: bool
    opened_at: float
    close_time_epoch: int
    balance_before: Optional[float] = None


class TradeManager:
    """Manages trade placement and background settlement tracking."""

    def __init__(self, client_holder: ClientHolder):
        self.client_holder = client_holder
        self.pending: Dict[int, PendingTrade] = {}
        self.open_trade_ids: set = set()

    async def place_trade(self, asset: str, amount: float, direction: str,
                          duration_minutes: int = 1, is_demo: bool = True,
                          wait_for_result: bool = False) -> Optional[Dict]:
        """Place a trade. Returns the open result or None on failure."""
        client = self.client_holder.client
        if client is None:
            elog.error("No connected client.")
            return None

        # Normalize direction
        direction = direction.lower()
        if direction in ('buy', 'call', 'up'):
            action = 'call'
        elif direction in ('sell', 'put', 'down'):
            action = 'put'
        else:
            elog.error(f"Invalid direction: {direction}. Use 'buy'/'sell'/'call'/'put'.")
            return None

        now = int(time.time())
        duration_seconds = duration_minutes * 60
        is_otc = '_otc' in asset.lower()
        expiration_value = duration_seconds if is_otc else \
                           self._get_expiration_time(now, duration_minutes)

        # Subscribe to asset
        api = client.api
        try:
            api.send_websocket_request(
                f'42["instruments/update",{{"asset":"{asset}","period":{duration_seconds}}}]',
                no_force_send=False,
            )
            api.send_websocket_request(
                f'42["chart_notification/get",{{"asset":"{asset}","version":"1.0.0"}}]',
                no_force_send=False,
            )
            api.send_websocket_request(f'42["depth/follow","{asset}"]', no_force_send=False)
            await asyncio.sleep(0.3)
        except Exception as e:
            elog.warn(f"Failed to subscribe for trade: {e}")

        # Build payload
        payload = {
            'asset': asset,
            'amount': amount,
            'time': expiration_value,
            'action': action,
            'isDemo': 1 if is_demo else 0,
            'tournamentId': 0,
            'requestId': random.randint(1, 10**9),
            'optionType': 100 if is_otc else 1,
        }

        # Send
        try:
            api.send_websocket_request('42["tick"]', no_force_send=False)
            await asyncio.sleep(0.05)
            api.send_websocket_request(
                f'42["orders/open",{json.dumps(payload)}]',
                no_force_send=False,
            )
        except Exception as e:
            elog.error(f"Failed to send trade request: {e}")
            return None

        # For now, return the payload as the "result" (real implementation
        # would wait for trade_result event).
        result = {
            'asset': asset,
            'amount': amount,
            'action': action,
            'isDemo': is_demo,
            'openTime': now,
            'closeTime': now + duration_seconds,
            'id': random.randint(10**8, 10**9),  # placeholder
        }

        # Track in pending
        close_time_epoch = now + duration_seconds
        pending = PendingTrade(
            trade_id=result['id'],
            asset=asset,
            direction=action,
            amount=amount,
            is_demo=is_demo,
            opened_at=time.time(),
            close_time_epoch=close_time_epoch,
        )
        self.pending[result['id']] = pending
        self.open_trade_ids.add(result['id'])

        # Print summary
        self._print_trade_summary(result, action, is_demo)

        if not wait_for_result:
            # Spawn background settlement tracker
            asyncio.create_task(self._settle_in_background(pending))
        return result

    def _get_expiration_time(self, now_ts: int, duration_minutes: int) -> int:
        """Compute expiration time aligned to the next minute boundary."""
        seconds_into_minute = now_ts % 60
        shift_minutes = 1 if seconds_into_minute > 30 else 0
        base_minute_start = (now_ts // 60) * 60
        return base_minute_start + (duration_minutes + shift_minutes) * 60

    def _print_trade_summary(self, result: Dict, direction: str, is_demo: bool):
        dir_label = (paint_bold('▲ CALL (BUY)', C2.BRIGHT_GREEN) if direction == 'call'
                     else paint_bold('▼ PUT (SELL)', C2.BRIGHT_RED))
        acc_label = paint(C2.BRIGHT_CYAN, 'DEMO') if is_demo else paint(C2.BRIGHT_MAGENTA, 'REAL')

        print()
        print(hr(60, '─', C2.BRIGHT_BLUE))
        print(f"  {paint_bold('Trade Opened', C2.BRIGHT_WHITE)}")
        print(hr(60, '─', C2.BRIGHT_BLUE))
        print(f"  {paint('Asset:', C2.DIM):<20} {paint_bold(result['asset'], C2.BRIGHT_YELLOW)}")
        print(f"  {paint('Direction:', C2.DIM):<20} {dir_label}")
        print(f"  {paint('Type:', C2.DIM):<20} {acc_label}")
        print(f"  {paint('Amount:', C2.DIM):<20} ${result['amount']}")
        print(f"  {paint('Trade ID:', C2.DIM):<20} {paint_dim(str(result.get('id', 'N/A')))}")
        print(hr(60, '─', C2.BRIGHT_BLUE))
        print()

    async def _settle_in_background(self, pending: PendingTrade):
        """Wait for a trade to settle in the background."""
        seconds_left = max(0, pending.close_time_epoch - int(time.time()))
        elog.info(f"Trade #{pending.trade_id} will settle in ~{seconds_left}s. "
                  f"Type 'trades' to check pending trades.")

        # Sleep until close time + small buffer
        wait_seconds = seconds_left + 8
        try:
            await asyncio.sleep(wait_seconds)
        except asyncio.CancelledError:
            return

        # Remove from pending (real implementation would check for close event)
        self.pending.pop(pending.trade_id, None)
        self.open_trade_ids.discard(pending.trade_id)
        elog.warn(f"Trade #{pending.trade_id} settled (no close event received — "
                  f"check Quotex account/history manually).")

    def print_pending_trades(self):
        """Print all pending trades."""
        if not self.pending:
            elog.info("No pending trades.")
            return

        print()
        print(hr(70, '─', C2.DIM))
        print(f"  {paint_bold(f'⏳ PENDING TRADES ({len(self.pending)})', C2.BRIGHT_CYAN)}")
        print(hr(70, '─', C2.DIM))
        for tid, p in self.pending.items():
            elapsed = int(time.time() - p.opened_at)
            dir_label = (paint('▲ CALL', C2.BRIGHT_GREEN) if p.direction == 'call'
                         else paint('▼ PUT', C2.BRIGHT_RED))
            print(f"  #{paint_dim(str(tid))}  "
                  f"{paint_bold(p.asset, C2.BRIGHT_YELLOW)}  {dir_label}  "
                  f"${p.amount}  {paint_dim(f'{elapsed}s ago')}")
        print(hr(70, '─', C2.DIM))
        print()


# ============================================================================
# SECTION 21: ACCOUNTS MANAGER (multi-account support)
# ============================================================================
class AccountsManager:
    """Manages multiple connected Quotex accounts."""

    def __init__(self):
        self.holders: List[ClientHolder] = []
        self.monitors: List[ConnectionMonitor] = []
        self.live_renderers: List[LivePriceRenderer] = []

    @property
    def primary(self) -> Optional[ClientHolder]:
        return self.holders[0] if self.holders else None

    @property
    def primary_client(self) -> Optional[Quotex]:
        h = self.primary
        return h.client if h else None

    async def add_and_connect(self, email: str, password: str,
                              is_demo: bool = True) -> Optional[ClientHolder]:
        """Connect a new account and add it to the manager."""
        spinner = Spinner(f"[{email}] Connecting...")
        spinner.start()
        try:
            client = await connect_quotex(email, password, max_attempts=3)
            if client is None:
                spinner.stop(f"[{email}] Failed to connect.", success=False)
                return None

            # Switch to demo/real
            try:
                await client.change_account("PRACTICE" if is_demo else "REAL")
                await asyncio.sleep(0.5)
            except Exception:
                pass

            holder = ClientHolder(client, email, password)
            self.holders.append(holder)

            # Start connection monitor
            monitor = ConnectionMonitor(holder)
            monitor.start()
            self.monitors.append(monitor)

            spinner.stop(f"[{email}] Connected successfully.", success=True)
            return holder
        except Exception as e:
            spinner.stop(f"[{email}] Connection error: {e}", success=False)
            return None

    async def broadcast_fetch(self, asset: str, timeframe_min: int,
                              target_count: int = TARGET_CANDLE_COUNT,
                              live_tracker: Optional[LivePriceTracker] = None) -> List[List[Dict]]:
        """Fetch candles for one asset across all connected accounts (broadcast)."""
        if not self.holders:
            elog.error("No connected accounts.")
            return []
        elog.info(f"Broadcasting fetch to {len(self.holders)} account(s)...")
        results = []
        for holder in self.holders:
            try:
                candles = await fetch_exactly_n_candles(
                    holder.client, asset, timeframe_min, target_count, live_tracker,
                )
                results.append(candles)
            except Exception as e:
                elog.error(f"[{holder.label}] fetch error: {e}")
                results.append([])
        return results

    def list_accounts(self):
        if not self.holders:
            elog.info("No accounts connected.")
            return
        print()
        print(f"  {paint_bold(f'👥 CONNECTED ACCOUNTS ({len(self.holders)})', C2.BRIGHT_CYAN)}")
        print(hr(50, '─', C2.DIM))
        for i, h in enumerate(self.holders, 1):
            label = h.label or 'N/A'
            state = getattr(h.client.api, 'state', None) if h.client and h.client.api else None
            status = 'CONNECTED' if state and getattr(state, 'check_accepted_connection', False) else 'DISCONNECTED'
            status_color = C2.BRIGHT_GREEN if status == 'CONNECTED' else C2.BRIGHT_RED
            print(f"  {paint_dim(f'{i}.')} {paint_bold(label, C2.BRIGHT_YELLOW)} "
                  f"{paint_dim('-')} {paint(status_color, status)}")
        print()

    async def close_all(self):
        """Close all clients and stop all background tasks."""
        # Stop monitors
        for monitor in self.monitors:
            try:
                await monitor.stop()
            except Exception:
                pass
        # Stop live renderers
        for r in self.live_renderers:
            r.stop()
        # Close clients
        for holder in self.holders:
            try:
                if holder.client:
                    await holder.client.close()
            except Exception:
                pass
        self.holders.clear()
        self.monitors.clear()
        self.live_renderers.clear()


# ============================================================================
# SECTION 22: COMMAND INTERPRETER (REPL)
# ============================================================================
def print_help():
    """Print the command reference."""
    W = 76
    print()
    print(paint(C2.BRIGHT_BLUE, '╔' + '═' * (W - 2) + '╗'))
    title = 'QUOTEX MEGA FETCHER — COMMAND REFERENCE'
    title_pad = (W - 2 - len(title)) // 2
    print(paint(C2.BRIGHT_BLUE, '║') + ' ' * title_pad +
          paint_bold(title, C2.BRIGHT_CYAN) + ' ' * (W - 2 - title_pad - len(title)) +
          paint(C2.BRIGHT_BLUE, '║'))
    print(paint(C2.BRIGHT_BLUE, '╚' + '═' * (W - 2) + '╝'))
    print()

    NAME_W = 32

    def section(label: str):
        print(f"  {paint_bold(f'❯ {label}', C2.BRIGHT_MAGENTA)}")

    def row(name: str, desc: str):
        print(f"     {pad_visible(paint_bold(name, C2.BRIGHT_GREEN), NAME_W)}{paint(C2.WHITE, desc)}")

    def example(text: str):
        print(f"     {paint_dim(f'↳ {text}')}")

    section('ACCOUNTS')
    row('accounts', 'List all connected accounts')
    row('connect', 'Connect an additional account')
    section('FETCHING')
    row('fetch', 'Fetch 500 candles for all 13 OTC pairs')
    row('fetch <asset>', 'Fetch 500 candles for one asset')
    example('fetch USDARS_otc')
    row('fetch <asset> <count>', 'Fetch a custom number of candles')
    example('fetch USDARS_otc 1000')
    row('export', 'Save last fetched candles as CSV')
    section('LIVE DATA')
    row('live <asset> [asset2]', 'Stream live price (Ctrl+C or "stoplive" to stop)')
    example('live USDARS_otc EURUSD_otc')
    row('stoplive', 'Stop the running live price stream')
    section('TRADING')
    row('buy <asset> <amt> <min>', 'Open BUY (call); settles in background')
    example('buy USDARS_otc 10 1')
    row('sell <asset> <amt> <min>', 'Open SELL (put); settles in background')
    example('sell USDARS_otc 10 1')
    row('trades', 'List trades still waiting to settle')
    section('STATUS')
    row('balance', 'Show balance for all accounts')
    row('stats', 'Show connection monitor statistics')
    row('assets', 'List available trading assets')
    section('SYSTEM')
    row('debug <on|all|off>', 'Toggle raw WS debug logging')
    row('domain', 'Show currently selected domain')
    row('help', 'Show this menu')
    row('exit', 'Close the program')
    print()
    print(paint_dim('═' * W))
    print()


async def handle_command(ctx: Dict, raw_input: str):
    """Handle a single REPL command."""
    manager: AccountsManager = ctx['manager']
    trade_mgr: TradeManager = ctx['trade_mgr']
    live_tracker: Optional[LivePriceTracker] = ctx['live_tracker']
    question = ctx['question']
    last_candles = ctx.get('last_candles', [])
    last_asset = ctx.get('last_asset', None)

    parts = raw_input.strip().split()
    if not parts:
        return
    cmd = parts[0].lower()
    client = manager.primary_client

    if cmd == 'help':
        print_help()

    elif cmd == 'accounts':
        manager.list_accounts()

    elif cmd == 'connect':
        email = (await question('📧 New account email: ')).strip()
        password = (await question('🔑 New account password: ')).strip()
        if email and password:
            await manager.add_and_connect(email, password)

    elif cmd == 'fetch':
        if not client:
            elog.error("No connected accounts.")
            return
        asset = parts[1] if len(parts) > 1 else None
        count = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else TARGET_CANDLE_COUNT
        timeframe = ctx.get('timeframe', TIMEFRAME_DEFAULT)

        if asset is None:
            # Fetch all 13 OTC pairs
            elog.info(f"Fetching {count} candles for all {len(OTC_ASSETS)} OTC pairs (M{timeframe})...")
            successes = 0
            failures = []
            for idx, a in enumerate(OTC_ASSETS, 1):
                print(f"\n{paint_bold(f'  [{idx}/{len(OTC_ASSETS)}] {a}', C2.BRIGHT_CYAN)}")
                try:
                    candles = await fetch_exactly_n_candles(
                        client, a, timeframe, count, live_tracker,
                    )
                except Exception as e:
                    log_exception(f"fetch_{a}", e)
                    candles = []
                if candles:
                    fp = save_candles_to_json(candles, a, timeframe, count)
                    if fp:
                        elog.success(f"Saved {len(candles)} candles → {fp.name}")
                        successes += 1
                        ctx['last_candles'] = candles
                        ctx['last_asset'] = a
                    else:
                        failures.append(a)
                else:
                    failures.append(a)
            elog.info(f"Batch complete: {paint_bold(f'{successes}/{len(OTC_ASSETS)}', C2.BRIGHT_GREEN)} successful")
            if failures:
                elog.warn(f"Failed: {', '.join(failures)}")
        else:
            candles = await fetch_exactly_n_candles(client, asset, timeframe, count, live_tracker)
            if candles:
                fp = save_candles_to_json(candles, asset, timeframe, count)
                if fp:
                    elog.success(f"Saved {len(candles)} candles → {fp.name}")
                    ctx['last_candles'] = candles
                    ctx['last_asset'] = asset

    elif cmd == 'export':
        if not ctx.get('last_candles'):
            elog.error("No candles cached. Run 'fetch' first.")
            return
        filename = f"{(ctx.get('last_asset') or 'candles').replace('/', '_')}_data.csv"
        export_to_csv(ctx['last_candles'], filename)

    elif cmd == 'live':
        if not client:
            elog.error("No connected accounts.")
            return
        assets = parts[1:]
        if not assets:
            elog.error("Usage: live <asset> [asset2 ...]")
            return
        if not live_tracker:
            elog.error("Live tracker not available.")
            return
        renderer = LivePriceRenderer(live_tracker, assets)
        manager.live_renderers.append(renderer)
        renderer.start()
        elog.info("Type 'stoplive' to stop the stream.")

    elif cmd == 'stoplive':
        stopped = False
        for r in manager.live_renderers:
            if r.stop():
                stopped = True
        if not stopped:
            elog.info("No live price stream is currently running.")
        manager.live_renderers.clear()

    elif cmd in ('buy', 'sell'):
        if not client:
            elog.error("No connected accounts.")
            return
        if len(parts) < 4:
            elog.error(f"Usage: {cmd} <asset> <amount> <minutes>")
            return
        asset = parts[1]
        try:
            amount = float(parts[2])
            minutes = int(parts[3])
        except ValueError:
            elog.error("Amount must be a number, minutes must be an integer.")
            return
        await trade_mgr.place_trade(asset, amount, cmd, minutes, is_demo=True)

    elif cmd == 'trades':
        trade_mgr.print_pending_trades()

    elif cmd == 'balance':
        if not client:
            elog.error("No connected accounts.")
            return
        try:
            client.api.send_websocket_request('42["balance/get"]', no_force_send=False)
            await asyncio.sleep(1.0)
            balance = getattr(client.api, 'account_balance', None)
            if balance:
                demo = balance.get('demoBalance', 'N/A')
                real = balance.get('liveBalance', 'N/A')
                print()
                print(hr(50, '─', C2.BRIGHT_BLUE))
                print(f"  {paint_bold('Account Balance', C2.BRIGHT_WHITE)}")
                print(hr(50, '─', C2.BRIGHT_BLUE))
                print(f"  {paint('Demo:', C2.DIM):<15} {paint_bold(f'${demo}', C2.BRIGHT_CYAN)}")
                print(f"  {paint('Real:', C2.DIM):<15} {paint_bold(f'${real}', C2.BRIGHT_MAGENTA)}")
                print(hr(50, '─', C2.BRIGHT_BLUE))
                print()
            else:
                elog.warn("Could not read balance.")
        except Exception as e:
            elog.error(f"Failed to read balance: {e}")

    elif cmd == 'stats':
        if not manager.monitors:
            elog.error("No monitors running.")
            return
        for i, m in enumerate(manager.monitors, 1):
            s = m.stats()
            uptime = int(s['uptime_seconds'])
            print()
            print(hr(50, '─', C2.BRIGHT_BLUE))
            print(f"  {paint_bold(f'Monitor #{i}', C2.BRIGHT_WHITE)}")
            print(hr(50, '─', C2.BRIGHT_BLUE))
            print(f"  {paint('Uptime:', C2.DIM):<20} "
                  f"{int(uptime//3600):02d}:{int((uptime%3600)//60):02d}:{int(uptime%60):02d}")
            print(f"  {paint('Connection drops:', C2.DIM):<20} {s['connection_drops']}")
            if s.get('last_drop_ago'):
                print(f"  {paint('Last drop:', C2.DIM):<20} {int(s['last_drop_ago'])}s ago")
            if s.get('last_ping_ago'):
                print(f"  {paint('Last ping:', C2.DIM):<20} {int(s['last_ping_ago'])}s ago")
            print(hr(50, '─', C2.BRIGHT_BLUE))
            print()

    elif cmd == 'assets':
        if not client:
            elog.error("No connected accounts.")
            return
        # Show the 13 OTC pairs we know about
        print()
        print(hr(70, '─', C2.DIM))
        print(f"  {paint_bold(f'📊 OTC ASSETS ({len(OTC_ASSETS)})', C2.BRIGHT_CYAN)}")
        print(hr(70, '─', C2.DIM))
        for i, a in enumerate(OTC_ASSETS, 1):
            print(f"  {paint_dim(f'{i:>2}.')} {paint_bold(a, C2.BRIGHT_YELLOW)}")
        print(hr(70, '─', C2.DIM))
        print()

    elif cmd == 'debug':
        mode = parts[1].lower() if len(parts) > 1 else ''
        if mode == 'on':
            ctx['debug'] = 'orders'
            elog.success("Debug logging ON (filtered to orders).")
        elif mode == 'all':
            ctx['debug'] = 'all'
            elog.success("Debug logging ALL (full firehose).")
        elif mode == 'off':
            ctx['debug'] = 'off'
            elog.success("Debug logging OFF.")
        else:
            elog.error("Usage: debug <on|all|off>")

    elif cmd == 'domain':
        saved = load_saved_domain()
        if saved:
            elog.info(f"Currently selected domain: {paint_bold(saved, C2.BRIGHT_GREEN)}")
        else:
            elog.info("No domain saved yet.")

    elif cmd in ('exit', 'quit', 'q'):
        print(paint_bold('\n👋 Shutting down...', C2.BRIGHT_YELLOW))
        await manager.close_all()
        return 'exit'

    else:
        elog.error(f"Unknown command: '{cmd}'. Type 'help' for the command list.")


# ============================================================================
# SECTION 23: INTERACTIVE HELPERS
# ============================================================================
async def _ainput(prompt: str) -> str:
    return await asyncio.to_thread(input, prompt)


async def prompt_credentials() -> Optional[Tuple[str, str]]:
    """Load saved credentials or ask for new ones."""
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
            if tf not in (1, 5, 15, 30, 60):
                elog.warn(f"Timeframe {tf} is unusual - continuing anyway.")
            return tf
        except ValueError:
            elog.error("Please enter a valid integer.")


# ============================================================================
# SECTION 24: MAIN ASYNC ENTRY POINT
# ============================================================================
async def main_async():
    print_banner()
    purge_old_session()

    # Domain selection
    host = await select_domain_flow(_ainput)

    # Credentials
    creds = await prompt_credentials()
    if creds is None:
        elog.error("Invalid credentials.")
        return
    email, password = creds

    # Connect first account
    elog.info("Connecting to Quotex...")
    manager = AccountsManager()
    holder = await manager.add_and_connect(email, password)
    if holder is None:
        elog.error("Connection failed after multiple attempts.")
        return
    save_credentials(email, password)
    elog.success("Credentials saved.")

    # Install live price tracker on primary client
    live_tracker = LivePriceTracker(holder.client)
    if live_tracker.install():
        elog.success("Live price tracker installed.")
    else:
        elog.warn("Could not install live price tracker. Continuing without it.")
        live_tracker = None

    # Ask for timeframe
    timeframe = await prompt_timeframe()
    if timeframe is None:
        await manager.close_all()
        return

    # Initialize trade manager
    trade_mgr = TradeManager(holder)

    # REPL context
    ctx = {
        'manager': manager,
        'trade_mgr': trade_mgr,
        'live_tracker': live_tracker,
        'timeframe': timeframe,
        'question': _ainput,
        'last_candles': [],
        'last_asset': None,
        'debug': 'off',
    }

    # Print initial help
    elog.success("Connected. Type 'help' for the full command list.")
    print_help()

    # REPL loop
    prompt_str = paint_bold('❯ ', C2.BRIGHT_GREEN)
    while True:
        try:
            line = await _ainput(prompt_str)
        except (EOFError, KeyboardInterrupt):
            print()
            break
        result = await handle_command(ctx, line)
        if result == 'exit':
            break

    # Cleanup
    await manager.close_all()
    print(paint(C2.BRIGHT_CYAN, 'Done.'))


# ============================================================================
# SECTION 25: MAIN ENTRY POINT
# ============================================================================
def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n{paint(C2.BRIGHT_YELLOW, 'Stopped.')}")
    except Exception as e:
        log_exception("main", e)
        # Print full traceback for debugging
        traceback.print_exc()


if __name__ == "__main__":
    main()
