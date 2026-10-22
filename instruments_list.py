#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quotex Instruments List Fetcher
================================
Fetches the complete list of tradeable assets (instruments) from Quotex
via the Socket.IO v4 binary protocol.

PROTOCOL
--------
After WebSocket authorization, the client sends a Socket.IO BINARY EVENT:

    451-["instruments/list",{"_placeholder":true,"num":0}]

The server responds with a single binary WebSocket frame containing the
msgpack-encoded instruments list (typically ~48 KB, ~200+ assets).

The instruments list is a list of dicts, each with keys like:
    asset     : "USDARS_otc"
    name      : "USD/ARS"
    type      : "currency"
    profit    : 92            (payout percentage)
    enabled   : true
    currency  : "USD"
    schedule  : [...trading sessions...]

USAGE
-----
    python3 instruments_list.py

After login, the script:
  1. Patches WebsocketClient.on_message to intercept binary frames.
  2. Sends the instruments/list request.
  3. Waits for the binary response (up to 30s).
  4. Decodes msgpack, parses asset names.
  5. Saves results to:
        instruments_data/instruments_<timestamp>.json   (full data)
        instruments_data/instruments_<timestamp>.txt     (asset names only)

REQUIREMENTS
------------
    pip install msgpack websocket-client certifi requests fake-useragent bs4
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

# msgpack is REQUIRED for decoding the binary instruments response.
try:
    import msgpack
except ImportError:
    print(f"{Colors.RED}ERROR: msgpack is required.{Colors.RESET}")
    print(f"  Install with: pip install msgpack")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================
OUTPUT_DIR = Path("instruments_data")
OUTPUT_DIR.mkdir(exist_ok=True)
RUN_TS = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_JSON = OUTPUT_DIR / f"instruments_{RUN_TS}.json"
OUTPUT_TXT = OUTPUT_DIR / f"instruments_{RUN_TS}.txt"

# How long to wait for the instruments/list binary response.
TIMEOUT_SECONDS = 30

# Minimum binary frame size to consider as a candidate instruments response.
# Small frames are usually pings/acks and should be ignored.
MIN_BINARY_SIZE = 1024

# After successful auth, the server may auto-push the instruments list.
# Wait this many seconds for an auto-push before sending our own request.
AUTO_PUSH_WAIT_SECONDS = 3.0


# ============================================================================
# INSTRUMENTS LIST FETCHER
# ============================================================================
class InstrumentsListFetcher:
    """Intercepts WebSocket binary frames to capture the instruments/list response.

    Patches WebsocketClient.on_message at runtime. When a large binary frame
    arrives, attempts to msgpack-decode it. If the decoded data looks like an
    instruments list (list of dicts with 'asset' or 'id' keys), it's captured.
    """

    def __init__(self, client: Quotex):
        self.client = client
        self.instruments_data: Optional[Any] = None
        self.received_event = asyncio.Event()
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
        """Intercept binary frames; chain text frames to the original handler."""
        # Always try to capture binary first (before the original handler,
        # which may raise on bytes when expecting str).
        if isinstance(msg, (bytes, bytearray)):
            try:
                self._try_capture_binary(bytes(msg))
            except Exception as e:
                logmsg(f"[instruments] binary capture error: {e}")
        # Chain to the original handler. Wrap in try/except because the
        # original handler does msg.decode("utf-8", errors="ignore") which
        # produces garbage for binary but should not crash.
        if self._original_on_message is not None:
            try:
                self._original_on_message(wss, msg)
            except Exception as e:
                # Suppress errors caused by feeding bytes to a str-only handler.
                logger_debug = False
                if logger_debug:
                    logmsg(f"[instruments] original handler raised: {e}")

    def _try_capture_binary(self, data: bytes) -> None:
        """Try to msgpack-decode a binary frame and detect the instruments list."""
        if self.instruments_data is not None:
            return  # already captured
        if len(data) < MIN_BINARY_SIZE:
            return  # too small — likely a ping/ack

        # Try msgpack first (Socket.IO v5 default for binary attachments).
        decoded = None
        try:
            decoded = msgpack.unpackb(data, raw=False, strict_map_key=False)
        except Exception:
            # Fallback: try JSON (in case the server uses JSON encoding)
            try:
                text = data.decode("utf-8", errors="ignore")
                if text.startswith(("[", "{")):
                    decoded = json.loads(text)
            except Exception:
                pass

        if decoded is None:
            return

        # The decoded data may be wrapped in several layers. Unwrap each one.
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

        for cand in candidates:
            if self._looks_like_instruments(cand):
                self.instruments_data = cand
                if not self.received_event.is_set():
                    self.received_event.set()
                logmsg(
                    f"[instruments] captured binary response: "
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
            if not any(k in item for k in ("asset", "id", "symbol")):
                return False
        return True

    async def request_instruments(self, timeout: float = TIMEOUT_SECONDS) -> Optional[Any]:
        """Send the instruments/list request and wait for the binary response."""
        api = self.client.api
        # Socket.IO BINARY EVENT: 451-["instruments/list",{"_placeholder":true,"num":0}]
        # The "_placeholder" pattern tells Socket.IO that arg 0 will be filled
        # in by a binary attachment. Since we have no actual binary data to
        # send (we're requesting, not sending), the placeholder is empty.
        request_str = '451-["instruments/list",{"_placeholder":true,"num":0}]'
        try:
            api.send_websocket_request(request_str, no_force_send=False)
            logmsg("[instruments] sent 451-['instruments/list',{...}]")
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
    """Normalize the instruments list into a list of dicts with stable keys."""
    if isinstance(data, dict):
        if isinstance(data.get("instruments"), list):
            data = data["instruments"]
        else:
            data = [data]
    if not isinstance(data, list):
        return []

    instruments: List[Dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        asset_id = item.get("asset") or item.get("id") or item.get("symbol")
        is_otc = isinstance(asset_id, str) and asset_id.endswith("_otc")
        instruments.append({
            "asset": asset_id,
            "name": item.get("name") or item.get("description"),
            "type": item.get("type") or item.get("asset_type"),
            "profit": item.get("profit") or item.get("payout"),
            "enabled": item.get("enabled"),
            "currency": item.get("currency"),
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
    print(f"{Colors.YELLOW}  Protocol:   Socket.IO v4 (msgpack binary){Colors.RESET}")
    print(f"{Colors.YELLOW}  Timeout:     {TIMEOUT_SECONDS}s{Colors.RESET}")
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
        # Give the WebSocket a moment to settle after auth.
        await asyncio.sleep(1.5)

        # Install the binary-frame interceptor.
        try:
            fetcher = InstrumentsListFetcher(client)
        except Exception as e:
            print(f"{Colors.RED}Failed to install interceptor: {e}{Colors.RESET}")
            return

        # Some Quotex servers auto-push instruments/list right after auth.
        # Wait briefly for an auto-push before sending our own request.
        logmsg(f"[instruments] waiting up to {AUTO_PUSH_WAIT_SECONDS:.1f}s for auto-push...")
        try:
            await asyncio.wait_for(
                fetcher.received_event.wait(),
                timeout=AUTO_PUSH_WAIT_SECONDS,
            )
            logmsg("[instruments] received auto-pushed instruments/list")
        except asyncio.TimeoutError:
            # No auto-push — send the explicit request.
            logmsg("[instruments] no auto-push; sending explicit request")
            await fetcher.request_instruments(timeout=TIMEOUT_SECONDS)

        if fetcher.instruments_data is None:
            print(f"\n{Colors.RED}No instruments/list response received.{Colors.RESET}")
            print(f"{Colors.YELLOW}Possible causes:{Colors.RESET}")
            print(f"  - Quotex changed the protocol")
            print(f"  - The connection died before the response arrived")
            print(f"  - The response was smaller than {MIN_BINARY_SIZE} bytes")
            return

        # Parse and save.
        instruments = parse_instruments(fetcher.instruments_data)
        if not instruments:
            print(f"{Colors.RED}Failed to parse instruments data.{Colors.RESET}")
            print(f"{Colors.YELLOW}Raw type: {type(fetcher.instruments_data).__name__}{Colors.RESET}")
            print(f"{Colors.YELLOW}Raw preview: {str(fetcher.instruments_data)[:200]}{Colors.RESET}")
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
