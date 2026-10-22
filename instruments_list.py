#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quotex Instruments List Fetcher
================================
Fetches the complete list of tradeable assets (instruments) from Quotex.

PROTOCOL (verified against the working Node.js implementation)
--------------------------------------------------------------
After WebSocket authorization, the server automatically pushes the
instruments list. The flow is:

  CLIENT → SERVER:   42["instruments/get"]                    (text event)
  SERVER → CLIENT:   451-["instruments/list",{"_placeholder":true,"num":0}]   (announcement, ~54 bytes)
  SERVER → CLIENT:   <binary frame>                            (~48 KB JSON array)

The binary frame is NOT msgpack-encoded — it is a JSON array with a
single leading 0x04 byte (Engine.IO MESSAGE binary marker). The
working pattern (confirmed by the Node.js reference) is:

    if isinstance(data, bytes) and data[0] == 0x04:
        json_str = data[1:].decode('utf-8', errors='ignore')
        instruments = json.loads(json_str)

Each instrument is a dict with keys like:
    asset, name, profit, enabled, type, currency, ...

USAGE
-----
    python3 instruments_list.py

After login, the script:
  1. Installs a binary-frame interceptor on WebsocketClient.on_message.
  2. Sends `42["instruments/get"]` to trigger a fresh response.
  3. Waits for the binary frame (up to 30s).
  4. Strips the 0x04 byte, decodes JSON, parses the instruments list.
  5. Saves results to:
        instruments_data/instruments_<timestamp>.json
        instruments_data/instruments_<timestamp>.txt

REQUIREMENTS
------------
    pip install websocket-client certifi requests fake-useragent bs4
"""

import os
import sys
import json
import time
import asyncio
from pathlib import Path
from datetime import datetime
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
)


# ============================================================================
# CONFIGURATION
# ============================================================================
OUTPUT_DIR = Path("instruments_data")
OUTPUT_DIR.mkdir(exist_ok=True)
RUN_TS = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_JSON = OUTPUT_DIR / f"instruments_{RUN_TS}.json"
OUTPUT_TXT = OUTPUT_DIR / f"instruments_{RUN_TS}.txt"

# How long to wait for the binary response after sending instruments/get.
TIMEOUT_SECONDS = 30

# Minimum binary frame size to consider as a candidate instruments response.
# Smaller frames are usually pings / acks and are ignored.
MIN_BINARY_SIZE = 512

# After successful auth, the server may auto-push the instruments list.
# Wait this many seconds for an auto-push before sending our own request.
AUTO_PUSH_WAIT_SECONDS = 3.0


# ============================================================================
# INSTRUMENTS LIST FETCHER
# ============================================================================
class InstrumentsListFetcher:
    """Intercepts WebSocket binary frames to capture the instruments/list response.

    Two-step detection (mirrors the working Node.js implementation):

    1. Watch for the text announcement `451-["instruments/list",{...}]` to
       confirm that a binary attachment is about to arrive. This sets the
       `expecting_binary` flag.

    2. When a binary frame arrives (and we are expecting one, or as a
       fallback for any frame >= MIN_BINARY_SIZE), strip the leading 0x04
       byte (Engine.IO binary marker) and decode the rest as JSON. If JSON
       parsing fails, fall back to msgpack.
    """

    def __init__(self, client: Quotex):
        self.client = client
        self.instruments_data: Optional[Any] = None
        self.received_event = asyncio.Event()
        self.expecting_binary = False
        self._original_on_message = None
        self._ws_client = None
        self._patch_message_handler()

    def _patch_message_handler(self) -> None:
        """Replace WebsocketClient.on_message with our interceptor."""
        api = self.client.api
        if api is None:
            raise RuntimeError("Quotex API is not initialized")
        ws_client = getattr(api, "websocket_client", None)
        if ws_client is None:
            raise RuntimeError("WebSocket client is not initialized")
        self._ws_client = ws_client
        self._original_on_message = ws_client.on_message
        ws_client.on_message = self._on_message_interceptor
        logmsg("[instruments] interceptor installed on WebsocketClient.on_message")

    def _on_message_interceptor(self, wss, msg) -> None:
        """Intercept both text and binary frames."""
        # First: handle binary frames (these are what we actually want).
        if isinstance(msg, (bytes, bytearray)):
            try:
                self._try_capture_binary(bytes(msg))
            except Exception as e:
                logmsg(f"[instruments] binary capture error: {e}")
        else:
            # Text frame — check if it's the instruments/list announcement.
            try:
                text = msg if isinstance(msg, str) else msg.decode("utf-8", errors="ignore")
                if "_placeholder" in text and "instruments/list" in text:
                    if not self.expecting_binary:
                        self.expecting_binary = True
                        logmsg("[instruments] received 451-['instruments/list',{...}] announcement; "
                               "expecting binary frame next")
            except Exception:
                pass

        # Chain to the original handler. Wrap in try/except because the
        # original handler does msg.decode("utf-8", errors="ignore") which
        # produces garbage for binary frames but should not crash.
        if self._original_on_message is not None:
            try:
                self._original_on_message(wss, msg)
            except Exception:
                pass

    def _try_capture_binary(self, data: bytes) -> None:
        """Try to decode a binary frame as the instruments list.

        Tries JSON first (with 0x04 byte strip — the working Node.js
        pattern), then falls back to msgpack.
        """
        if self.instruments_data is not None:
            return  # already captured
        if len(data) < MIN_BINARY_SIZE:
            return  # too small — likely a ping/ack

        decoded = None
        decode_strategy = "none"

        # Strategy 1: Strip leading 0x04 byte, then JSON parse.
        # This is the working Node.js pattern.
        candidate = data
        if len(data) > 0 and data[0] == 0x04:
            candidate = data[1:]

        try:
            text = candidate.decode("utf-8", errors="ignore")
            # Find the first JSON array/object marker — Quotex sends a
            # JSON array, so '[' should be at index 0 (after stripping 0x04).
            # But to be robust, search for the first '[' or '{' character.
            start_idx = -1
            for i, ch in enumerate(text):
                if ch in ('[', '{'):
                    start_idx = i
                    break
            if start_idx >= 0:
                json_str = text[start_idx:]
                parsed = json.loads(json_str)
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
                import msgpack  # optional dependency
                decoded = msgpack.unpackb(data, raw=False, strict_map_key=False)
                decode_strategy = "msgpack"
            except ImportError:
                pass
            except Exception:
                pass

        if decoded is None:
            return  # could not decode this frame

        # Unwrap Socket.IO envelope if present.
        candidates: List[Any] = []
        if isinstance(decoded, list):
            candidates.append(decoded)
            # Socket.IO envelope: [event_name, payload]
            if len(decoded) == 2 and isinstance(decoded[0], str):
                candidates.append(decoded[1])
        elif isinstance(decoded, dict):
            candidates.append(decoded)
            if isinstance(decoded.get("instruments"), list):
                candidates.append(decoded["instruments"])
            if isinstance(decoded.get("list"), list):
                candidates.append(decoded["list"])

        for cand in candidates:
            if self._looks_like_instruments(cand):
                self.instruments_data = cand
                if not self.received_event.is_set():
                    self.received_event.set()
                logmsg(
                    f"[instruments] captured binary response via {decode_strategy}: "
                    f"{len(cand)} entries, {len(data):,} bytes"
                )
                return

    @staticmethod
    def _looks_like_instruments(data: Any) -> bool:
        """Heuristic: is this a list of instrument dicts?"""
        if not isinstance(data, list) or len(data) < 5:
            return False
        sample = data[:5]
        for item in sample:
            if not isinstance(item, dict):
                return False
            if not any(k in item for k in ("asset", "id", "symbol", "name")):
                return False
        return True

    async def request_instruments(self, timeout: float = TIMEOUT_SECONDS) -> Optional[Any]:
        """Send the instruments/get request and wait for the binary response.

        Uses `42["instruments/get"]` (the correct client request format
        confirmed by the working Node.js implementation). The server
        responds with:
          1. `451-["instruments/list",{...}]` text announcement
          2. Binary frame containing the JSON instruments array
        """
        api = self.client.api
        try:
            api.send_websocket_request('42["instruments/get"]', no_force_send=False)
            logmsg('[instruments] sent 42["instruments/get"]')
        except Exception as e:
            logmsg(f"[instruments] failed to send request: {e}")
            return None

        try:
            await asyncio.wait_for(self.received_event.wait(), timeout=timeout)
            return self.instruments_data
        except asyncio.TimeoutError:
            logmsg(f"[instruments] timeout after {timeout}s — no binary response")
            return None

    def restore(self) -> None:
        """Restore the original on_message handler."""
        try:
            if (
                self._ws_client is not None
                and self._original_on_message is not None
            ):
                self._ws_client.on_message = self._original_on_message
                logmsg("[instruments] original handler restored")
        except Exception:
            pass


# ============================================================================
# PARSING & OUTPUT
# ============================================================================
def parse_instruments(data: Any) -> List[Dict[str, Any]]:
    """Normalize the instruments list into a list of dicts with stable keys.

    The Quotex server returns instruments in two possible shapes:
      1. List of dicts: [{"asset": "USDARS_otc", "profit": 92, ...}, ...]
      2. List of arrays: [["id", "USDARS_otc", "USD/ARS", ..., true], ...]

    Both are handled here.
    """
    if isinstance(data, dict):
        if isinstance(data.get("instruments"), list):
            data = data["instruments"]
        elif isinstance(data.get("list"), list):
            data = data["list"]
        else:
            data = [data]
    if not isinstance(data, list):
        return []

    instruments: List[Dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict):
            asset_id = item.get("asset") or item.get("id") or item.get("symbol")
            is_otc = isinstance(asset_id, str) and asset_id.endswith("_otc")
            instruments.append({
                "asset": asset_id,
                "name": item.get("name") or item.get("displayName") or item.get("description"),
                "type": item.get("type") or item.get("asset_type"),
                "profit": item.get("profit") or item.get("payout"),
                "enabled": item.get("enabled") if "enabled" in item else item.get("open"),
                "currency": item.get("currency"),
                "is_otc": is_otc,
            })
        elif isinstance(item, list) and len(item) >= 6:
            # Array form: [id, symbol, displayName, ..., payout, ..., open]
            # (matching the Node.js printAssetsTable logic)
            asset_id = item[1] if len(item) > 1 else None
            display_name = item[2] if len(item) > 2 else None
            payout = item[5] if len(item) > 5 else None
            is_open = bool(item[14]) if len(item) > 14 else None
            is_otc = isinstance(asset_id, str) and asset_id.endswith("_otc")
            instruments.append({
                "asset": asset_id,
                "name": display_name,
                "type": None,
                "profit": payout,
                "enabled": is_open,
                "currency": None,
                "is_otc": is_otc,
            })
    return instruments


def save_outputs(instruments: List[Dict[str, Any]]) -> None:
    """Save full JSON + plain-text asset names."""
    # Full JSON
    payload = {
        "fetch_time": datetime.now().isoformat(timespec="seconds"),
        "fetch_timestamp": int(time.time()),
        "total_instruments": len(instruments),
        "instruments": instruments,
    }
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"{Colors.GREEN}OK Saved full list to:{Colors.RESET}")
    print(f"  {Colors.CYAN}{OUTPUT_JSON.absolute()}{Colors.RESET}")

    # Plain-text asset names (one per line, sorted)
    asset_names = sorted({i["asset"] for i in instruments if i["asset"]})
    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        for name in asset_names:
            f.write(name + "\n")
    print(f"{Colors.GREEN}OK Saved {len(asset_names)} asset names to:{Colors.RESET}")
    print(f"  {Colors.CYAN}{OUTPUT_TXT.absolute()}{Colors.RESET}")


def print_summary(instruments: List[Dict[str, Any]]) -> None:
    """Print a summary to the console."""
    otc = [i for i in instruments if i.get("is_otc")]
    non_otc = [i for i in instruments if not i.get("is_otc")]
    enabled = [i for i in instruments if i.get("enabled")]

    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Instruments Summary{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"  Total instruments:   {len(instruments)}")
    print(f"  Enabled:             {len(enabled)}")
    print(f"  OTC pairs:           {len(otc)}")
    print(f"  Non-OTC:             {len(non_otc)}")

    if otc:
        print(f"\n{Colors.CYAN}OTC assets found:{Colors.RESET}")
        for i in sorted(otc, key=lambda x: (x["asset"] or "")):
            profit_str = f"profit={i['profit']}%" if i.get("profit") is not None else ""
            enabled_str = "enabled" if i.get("enabled") else "disabled"
            print(f"  {(i['asset'] or ''):<20} {profit_str:<15} {enabled_str}")


# ============================================================================
# INTERACTIVE HELPERS
# ============================================================================
async def _ainput(prompt: str) -> str:
    """Async input() that does NOT block the event loop."""
    return await asyncio.to_thread(input, prompt)


async def prompt_credentials() -> Optional[tuple]:
    """Load saved credentials or ask for new ones. Returns (email, password) or None."""
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


# ============================================================================
# MAIN
# ============================================================================
async def main_async() -> None:
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Quotex Instruments List Fetcher{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.YELLOW}  Output dir: {OUTPUT_DIR.absolute()}{Colors.RESET}")
    print(f"{Colors.YELLOW}  Protocol:  Socket.IO v4 (JSON in binary frame){Colors.RESET}")
    print(f"{Colors.YELLOW}  Timeout:   {TIMEOUT_SECONDS}s{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")

    purge_old_session()

    creds = await prompt_credentials()
    if creds is None:
        print(f"{Colors.RED}Invalid credentials.{Colors.RESET}")
        return
    email, password = creds

    # Connect to Quotex (reuses OTC_canda_ logic).
    logmsg("Connecting to Quotex...")
    client = await connect_quotex(email, password, max_attempts=3)
    if client is None:
        print(f"\n{Colors.RED}Connection failed after multiple attempts.{Colors.RESET}")
        return
    save_credentials(email, password)
    print(f"{Colors.GREEN}Credentials saved.{Colors.RESET}\n")

    fetcher: Optional[InstrumentsListFetcher] = None
    try:
        # Install the binary-frame interceptor IMMEDIATELY (before any
        # further waits). The server may already be pushing the instruments
        # list from the auto-trigger sent by on_open (`42["instruments/get"]`).
        try:
            fetcher = InstrumentsListFetcher(client)
        except Exception as e:
            print(f"{Colors.RED}Failed to install interceptor: {e}{Colors.RESET}")
            return

        # Brief window for the auto-push (sent during on_open) to arrive.
        # If the auto-push arrives within this window, we're done.
        if fetcher.received_event.is_set():
            logmsg("[instruments] captured auto-pushed instruments/list")
        else:
            logmsg(f"[instruments] waiting up to {AUTO_PUSH_WAIT_SECONDS:.1f}s for auto-push...")
            try:
                await asyncio.wait_for(
                    fetcher.received_event.wait(),
                    timeout=AUTO_PUSH_WAIT_SECONDS,
                )
                logmsg("[instruments] received auto-pushed instruments/list")
            except asyncio.TimeoutError:
                # No auto-push arrived — send the explicit request.
                # This triggers a fresh server response.
                logmsg("[instruments] no auto-push; sending explicit 42['instruments/get']")
                await fetcher.request_instruments(timeout=TIMEOUT_SECONDS)

        if fetcher.instruments_data is None:
            print(f"\n{Colors.RED}No instruments/list response received.{Colors.RESET}")
            print(f"{Colors.YELLOW}Diagnostic information:{Colors.RESET}")
            print(f"  - expecting_binary flag: {fetcher.expecting_binary}")
            print(f"{Colors.YELLOW}Possible causes:{Colors.RESET}")
            print(f"  - The WebSocket connection died before the response arrived")
            print(f"  - Quotex changed the protocol")
            print(f"  - Login failed silently")
            return

        # Parse and save.
        instruments = parse_instruments(fetcher.instruments_data)
        if not instruments:
            print(f"{Colors.RED}Failed to parse instruments data.{Colors.RESET}")
            print(f"{Colors.YELLOW}Raw type: {type(fetcher.instruments_data).__name__}{Colors.RESET}")
            preview = str(fetcher.instruments_data)[:300]
            print(f"{Colors.YELLOW}Raw preview: {preview}{Colors.RESET}")
            return

        print(f"\n{Colors.GREEN}OK Received {len(instruments)} instruments{Colors.RESET}")
        save_outputs(instruments)
        print_summary(instruments)

    finally:
        if fetcher is not None:
            fetcher.restore()
        try:
            await client.close()
        except Exception:
            pass
        print(f"\n{Colors.CYAN}Done.{Colors.RESET}")


def main() -> None:
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Stopped.{Colors.RESET}")
    except Exception as e:
        log_exception("main", e)


if __name__ == "__main__":
    main()
