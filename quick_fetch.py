#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick Fetch — 500 candles per asset for all 13 OTC pairs
=========================================================
A lean, fast fetcher that downloads exactly 500 candles per asset
(no more, no less) and saves them to candles_otc_data/ as JSON files.

KEY FEATURES (ported from the working large file wedsoket_.py)
--------------------------------------------------------------
1. GAP-FILLING via _fill_missing_slots (ported verbatim):
   - Any missing time slot between candles is filled with a flat candle
     (open = high = low = close = previous close, volume=0).
   - max_gap = 1440 slots (= 1 day for M1) — covers weekend/market-closed gaps.

2. LIVE PRICE via depth/follow + quotes/stream:
   - Subscribes to real-time price ticks for each asset while fetching.
   - The current price is logged so the user can verify the market is alive.

3. FIXED COUNT: exactly 500 candles per asset.
   - For M1: ~500 minutes ≈ 8.3 hours of recent history.
   - For M5: ~500 candles ≈ 1.7 days of recent history.
   - The fetcher uses overlapping chunks + deduplication to land on exactly 500.

USAGE
-----
    python3 quick_fetch.py

After login, the script asks ONLY for the timeframe (1, 5, 15, 30, 60).
Then it fetches 500 candles for each of the 13 OTC assets in sequence.

OUTPUT
------
    candles_otc_data/{asset}_{timeframe}m_500c_{8-char-hex}.json
"""

import os
import sys
import json
import time
import random
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, OrderedDict
from typing import Any, Dict, List, Optional

# Reuse the Quotex client from OTC_canda_.py (same folder)
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
)


# ============================================================================
# CONFIGURATION
# ============================================================================
TARGET_CANDLE_COUNT = 500          # exactly 500 candles per asset
TIMEFRAME_DEFAULT = 1              # M1 default
MAX_FETCH_RETRIES = 5
RETRY_BACKOFF_BASE = 2
RETRY_BACKOFF_MAX = 15
RETRY_BACKOFF = 0.5                # delay between overlapping chunk fetches
LIVE_PRICE_LISTEN_SECONDS = 2.0    # how long to listen for live ticks per asset
GAP_FILL_MAX_SLOTS = 1440          # max gaps to fill (= 1 day for M1)

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


# ============================================================================
# GAP-FILLING ENGINE (ported from wedsoket_.py)
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
# LIVE PRICE TRACKER
# ============================================================================
class LivePriceTracker:
    """Tracks live price ticks for one or more assets via WebSocket.

    Subscribes via:
      42["depth/follow","ASSET_otc"]
      42["quotes/stream"]          (auto-pushed by Quotex after depth/follow)
      42["instruments/update",{"asset":"ASSET_otc","period":60}]

    The Quotex server pushes ticks in messages like:
      [[asset_name, time, price], ...]    (a list of tick arrays)

    These arrive as text frames via WebsocketClient.on_message.
    """

    def __init__(self, client: Quotex):
        self.client = client
        self.prices: Dict[str, float] = {}
        self.ticks_seen: Dict[str, int] = defaultdict(int)
        self._installed = False
        self._original_on_message = None

    def install(self) -> bool:
        """Patch WebsocketClient.on_message to also capture live ticks."""
        api = self.client.api
        if api is None:
            return False
        ws_client = getattr(api, "websocket_client", None)
        if ws_client is None:
            return False
        self._original_on_message = ws_client.on_message
        ws_client.on_message = self._on_message
        self._installed = True
        return True

    def restore(self) -> None:
        if self._installed and self._original_on_message is not None:
            try:
                api = self.client.api
                ws_client = getattr(api, "websocket_client", None)
                if ws_client:
                    ws_client.on_message = self._original_on_message
            except Exception:
                pass
            self._installed = False

    def _on_message(self, wss, msg) -> None:
        """Intercept messages and look for live price tick arrays."""
        try:
            if isinstance(msg, (bytes, bytearray)):
                # Pass through binary frames; the original handler will deal with them.
                pass
            else:
                text = msg if isinstance(msg, str) else msg.decode("utf-8", errors="ignore")
                # Live tick format from Quotex:
                #   42["quotes/stream",[[asset, time, price], ...]]
                #   42[<event>,[[asset, time, price], ...]]
                # We look for a list-of-lists where each inner list has 3+ items:
                #   [str_asset, int_time, float_price]
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
            # Could be a list of ticks directly: [[asset, time, price], ...]
            if payload and isinstance(payload[0], list):
                candidates = payload
            # Or a dict containing 'data' key
            elif isinstance(payload, dict) and isinstance(payload.get("data"), list):
                candidates = payload["data"]
        for tick in candidates:
            if isinstance(tick, list) and len(tick) >= 3:
                asset = tick[0]
                price = tick[2]
                if isinstance(asset, str) and isinstance(price, (int, float)):
                    self.prices[asset] = float(price)
                    self.ticks_seen[asset] += 1

    def subscribe(self, asset: str, period: int = 60) -> None:
        """Send the subscribe messages for live price updates."""
        api = self.client.api
        try:
            api.send_websocket_request(
                f'42["instruments/update",{{"asset":"{asset}","period":{period}}}]',
                no_force_send=False,
            )
            api.send_websocket_request(f'42["depth/follow","{asset}"]', no_force_send=False)
            api.send_websocket_request('42["chart_notification/get"]', no_force_send=False)
        except Exception as e:
            logmsg(f"[live] failed to subscribe {asset}: {e}")

    def unsubscribe(self, asset: str) -> None:
        """Stop receiving live updates for an asset."""
        api = self.client.api
        try:
            api.send_websocket_request(f'42["depth/unfollow","{asset}"]', no_force_send=False)
        except Exception:
            pass

    def get_price(self, asset: str) -> Optional[float]:
        return self.prices.get(asset)


# ============================================================================
# JSON SAVER (compatible with OTC_canda_.py format)
# ============================================================================
def save_candles_to_json(candles: List[Dict], asset: str, timeframe_min: int,
                          target_count: int) -> Optional[Path]:
    """Saves candles directly to candles_otc_data/{asset}_{tf}m_{count}c_{hex}.json"""
    if not candles:
        logmsg("No candles to save.")
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
# FETCH LOGIC — 500 candles with overlapping chunks + gap-filling
# ============================================================================
async def fetch_exactly_n_candles(client: Quotex, asset: str, timeframe_min: int,
                                   target_count: int = TARGET_CANDLE_COUNT,
                                   live_tracker: Optional[LivePriceTracker] = None) -> List[Dict]:
    """Fetch exactly `target_count` candles for `asset`.

    Strategy (mirrors the chunked fetch in wedsoket_.py):
      1. Subscribe to live price (so we know the market is alive).
      2. Fetch overlapping chunks backwards from "now" using Quotex's
         history API.
      3. Deduplicate by timestamp.
      4. Apply _fill_missing_slots to fill any gaps with flat candles.
      5. Return exactly target_count candles (truncate from the start
         if we got more, pad with flat candles if we got fewer).

    Returns a sorted list of exactly `target_count` candle dicts.
    """
    period_seconds = int(timeframe_min * 60)
    display_name = f"{asset} (M{timeframe_min})"
    print(f"\n  {Colors.BOLD}{Colors.CYAN}Fetching {target_count} candles — {display_name}{Colors.RESET}")

    # Subscribe to live price
    if live_tracker:
        live_tracker.subscribe(asset, period=60)
        # Listen briefly for live ticks
        await asyncio.sleep(LIVE_PRICE_LISTEN_SECONDS)
        live_price = live_tracker.get_price(asset)
        if live_price is not None:
            print(f"  {Colors.GREEN}● Live price: {live_price}{Colors.RESET} "
                  f"({live_tracker.ticks_seen[asset]} ticks seen)")
        else:
            print(f"  {Colors.YELLOW}○ No live ticks received in "
                  f"{LIVE_PRICE_LISTEN_SECONDS}s — market may be closed{Colors.RESET}")

    # Compute the fetch span
    now_ts = int(time.time())
    target_end_ts = now_ts - (target_count * period_seconds)
    timeout = max(60, target_count * 5)  # 5s per candle as safety margin

    candles_map: Dict[int, Dict] = {}
    fetch_start = time.time()

    # Fetch in overlapping chunks of ~60 candles, stepping back ~50 candles each time.
    CHUNK_CANDLES = 60
    OVERLAP_CANDLES = 10
    chunk_offset = CHUNK_CANDLES * period_seconds
    step_offset = (CHUNK_CANDLES - OVERLAP_CANDLES) * period_seconds

    current_time = now_ts
    chunks_fetched = 0
    max_chunks = max(40, (target_count // (CHUNK_CANDLES - OVERLAP_CANDLES)) + 10)
    consecutive_empty = 0

    while len(candles_map) < target_count and chunks_fetched < max_chunks:
        # Batch of 3 chunks in parallel for speed
        BATCH = 3
        batch_times = []
        t = current_time
        for _ in range(BATCH):
            batch_times.append(t)
            t -= step_offset

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
                logmsg(f"  chunk fetch error at {int(fetch_time)}: {e}")
                return []

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
                logmsg(f"  {Colors.YELLOW}Reached end of available data.{Colors.RESET}")
                break
        else:
            consecutive_empty = 0
            current_time = batch_oldest - (OVERLAP_CANDLES * period_seconds)

        # Progress print
        elapsed = time.time() - fetch_start
        pct = min(len(candles_map) / target_count, 1.0)
        bar_len = 25
        filled = int(bar_len * pct)
        bar = '#' * filled + '-' * (bar_len - filled)
        sys.stdout.write(
            f"\r  {Colors.CYAN}[{bar}]{Colors.RESET} "
            f"{pct*100:5.1f}% | "
            f"{Colors.GREEN}{len(candles_map):>4}{Colors.RESET}/{target_count} | "
            f"{int(elapsed):>3}s   "
        )
        sys.stdout.flush()

    print()  # newline after progress bar

    if not candles_map:
        logmsg(f"  {Colors.RED}No candles fetched.{Colors.RESET}")
        return []

    # Sort by time
    candles = sorted(candles_map.values(), key=lambda x: x['time'])

    # Apply gap-filling
    before_fill = len(candles)
    candles = _fill_missing_slots(candles, period_seconds, max_gap=GAP_FILL_MAX_SLOTS)
    after_fill = len(candles)
    filled_count = after_fill - before_fill
    if filled_count > 0:
        logmsg(f"  {Colors.YELLOW}Filled {filled_count} gap slots with flat candles.{Colors.RESET}")

    # Truncate to exactly target_count (take the most recent N)
    if len(candles) > target_count:
        candles = candles[-target_count:]
    elif len(candles) < target_count:
        # Pad at the start with flat candles if we got fewer than requested
        first_ts = candles[0]['time']
        last_close = candles[0]['open']
        deficit = target_count - len(candles)
        for i in range(deficit, 0, -1):
            candles.insert(0, {
                'time': first_ts - i * period_seconds,
                'open': last_close, 'high': last_close,
                'low': last_close, 'close': last_close, 'volume': 0,
            })
        logmsg(f"  {Colors.YELLOW}Padded {deficit} candles at the start (insufficient history).{Colors.RESET}")

    # Unsubscribe from live price for this asset (will resubscribe for the next)
    if live_tracker:
        live_tracker.unsubscribe(asset)

    elapsed = time.time() - fetch_start
    logmsg(
        f"  {Colors.GREEN}OK Fetched {len(candles)} candles in "
        f"{int(elapsed//60):02d}:{int(elapsed%60):02d}{Colors.RESET} — {display_name}"
    )
    return candles


# ============================================================================
# INTERACTIVE MAIN
# ============================================================================
async def _ainput(prompt: str) -> str:
    return await asyncio.to_thread(input, prompt)


async def prompt_timeframe() -> Optional[int]:
    while True:
        try:
            raw = (await _ainput(
                f"{Colors.YELLOW}Timeframe in minutes (1, 5, 15, 30, 60) [default: 1]: {Colors.RESET}"
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
                print(f"{Colors.RED}Timeframe must be positive.{Colors.RESET}")
                continue
            if tf not in (1, 5, 15, 30, 60):
                print(f"{Colors.YELLOW}Warning: timeframe {tf} is unusual - continuing anyway.{Colors.RESET}")
            return tf
        except ValueError:
            print(f"{Colors.RED}Please enter a valid integer.{Colors.RESET}")


async def prompt_credentials() -> Optional[tuple]:
    creds = load_credentials()
    if creds:
        print(f"{Colors.GREEN}Found saved credentials for: {creds['email']}{Colors.RESET}")
        use_saved = (await _ainput(
            f"{Colors.YELLOW}Use saved credentials? (Y/n): {Colors.RESET}"
        )).strip().lower()
        if use_saved in ("y", "", "yes"):
            return creds["email"], creds["password"]
    print(f"{Colors.CYAN}Enter your Quotex credentials:{Colors.RESET}")
    email = (await _ainput(f"{Colors.YELLOW}Email: {Colors.RESET}")).strip()
    password = (await _ainput(f"{Colors.YELLOW}Password: {Colors.RESET}")).strip()
    if not email or not password:
        return None
    return email, password


def print_banner():
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Quick Fetch — 500 candles per asset{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.YELLOW}  Output dir:   {CANDLES_DIR.absolute()}{Colors.RESET}")
    print(f"{Colors.YELLOW}  Target count: {TARGET_CANDLE_COUNT} candles per asset{Colors.RESET}")
    print(f"{Colors.YELLOW}  Assets:       {len(OTC_ASSETS)} OTC pairs{Colors.RESET}")
    print(f"{Colors.YELLOW}  Gap-filling:  ENABLED (max_gap={GAP_FILL_MAX_SLOTS} slots){Colors.RESET}")
    print(f"{Colors.YELLOW}  Live price:   ENABLED (depth/follow + quotes/stream){Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")


async def main_async():
    print_banner()
    purge_old_session()

    creds = await prompt_credentials()
    if creds is None:
        print(f"{Colors.RED}Invalid credentials.{Colors.RESET}")
        return
    email, password = creds

    logmsg("Connecting to Quotex...")
    client = await connect_quotex(email, password, max_attempts=3)
    if client is None:
        print(f"\n{Colors.RED}Connection failed after multiple attempts.{Colors.RESET}")
        return
    save_credentials(email, password)
    print(f"{Colors.GREEN}Credentials saved.{Colors.RESET}\n")

    timeframe = await prompt_timeframe()
    if timeframe is None:
        print(f"\n{Colors.YELLOW}Stopped.{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}Summary:{Colors.RESET}")
    print(f"  Timeframe:     M{timeframe}")
    print(f"  Assets:        {len(OTC_ASSETS)} OTC pairs")
    print(f"  Per asset:     {TARGET_CANDLE_COUNT} candles")
    print(f"  Total:         {TARGET_CANDLE_COUNT * len(OTC_ASSETS):,} candles")
    print(f"  Output dir:    {CANDLES_DIR.absolute()}")
    print(f"\n{Colors.YELLOW}Starting in 2 seconds... (Ctrl+C to cancel){Colors.RESET}")
    await asyncio.sleep(2)

    # Install live price tracker
    live_tracker = LivePriceTracker(client)
    if live_tracker.install():
        logmsg(f"{Colors.GREEN}[live] Live price tracker installed.{Colors.RESET}")
    else:
        logmsg(f"{Colors.YELLOW}[live] Could not install live price tracker. Continuing without it.{Colors.RESET}")
        live_tracker = None

    total = len(OTC_ASSETS)
    successes = 0
    failures = []
    try:
        for idx, asset in enumerate(OTC_ASSETS, 1):
            print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}  [{idx}/{total}] {asset}{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

            try:
                candles = await fetch_exactly_n_candles(
                    client, asset, timeframe,
                    target_count=TARGET_CANDLE_COUNT,
                    live_tracker=live_tracker,
                )
            except Exception as e:
                log_exception(f"fetch_{asset}", e)
                candles = []

            if candles:
                fp = save_candles_to_json(candles, asset, timeframe, TARGET_CANDLE_COUNT)
                if fp:
                    print(f"{Colors.GREEN}OK Saved {len(candles)} candles → {fp.name}{Colors.RESET}")
                    successes += 1
                else:
                    print(f"{Colors.RED}Failed to save file for {asset}.{Colors.RESET}")
                    failures.append(asset)
            else:
                print(f"{Colors.RED}No candles fetched for {asset}.{Colors.RESET}")
                failures.append(asset)
    finally:
        if live_tracker:
            live_tracker.restore()
        try:
            await client.close()
        except Exception:
            pass

    # Final summary
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Batch complete{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"  Successful: {Colors.GREEN}{successes}/{total}{Colors.RESET}")
    if failures:
        print(f"  Failed:     {Colors.RED}{len(failures)} — {', '.join(failures)}{Colors.RESET}")
    print(f"  Output dir: {Colors.YELLOW}{CANDLES_DIR.absolute()}{Colors.RESET}")


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Stopped.{Colors.RESET}")
    except Exception as e:
        log_exception("main", e)


if __name__ == "__main__":
    main()
