"""
EnvStego — verify_token_security.py
Security verification of the 3T hardware token's BLE protocol, run against the real device.

Confirms the firmware rejects the requests its security model says it should. It only
talks to the token this PC is paired with and changes no secrets. Output is used as
evidence in the report's evaluation section.

Checks (each prints PASS / FAIL):
  A. Unpaired client          — a REQUEST before any HELLO, and a REQUEST sealed with
                                a random auth key (a client that never paired), are refused.
  B. Repeated request         — a valid request sent a second time is refused, both
                                against a consumed challenge and against a fresh one.
  C. 5-failure lockout        — five bad requests lock the token; the next message is
                                refused with LOCKED_OUT.

Usage (from the Python/ directory):
    # Pair first if this PC is not paired yet:
    python tools/verify_token_security.py --pair COM3
    # Then run the checks:
    python tools/verify_token_security.py
    # Optionally confirm the lockout clears after 30 s:
    python tools/verify_token_security.py --wait-recovery
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent          # .../Python
sys.path.insert(0, str(APP_DIR))

from bleak import BleakClient                              # noqa: E402

import token_comms as tc                                   # noqa: E402

RECV_TIMEOUT = 6.0
results: list[tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str = ""):
    results.append((name, passed, detail))
    tag = "PASS" if passed else "FAIL"
    print(f"  [{tag}] {name}" + (f"  — {detail}" if detail else ""))


def err_code(msg: bytes):
    """Return the error code if msg is an ERROR frame, else None."""
    if msg and msg[0] == tc.MSG_ERROR and len(msg) > 1:
        return msg[1]
    return None


class Link:
    """Thin BLE transport to the token: one notify inbox, write-and-wait helper."""

    def __init__(self, mac: str, uuid: str):
        self._mac, self._uuid = mac, uuid
        self._client = None
        self._inbox: asyncio.Queue[bytes] = asyncio.Queue()

    async def __aenter__(self):
        self._client = BleakClient(self._mac, timeout=10.0,
                                   winrt={"use_cached_services": False})
        await self._client.__aenter__()
        await self._client.start_notify(
            self._uuid, lambda _s, data: self._inbox.put_nowait(bytes(data)))
        return self

    async def __aexit__(self, *exc):
        try:
            await self._client.stop_notify(self._uuid)
        except Exception:
            pass
        await self._client.__aexit__(*exc)

    async def send(self, data: bytes) -> bytes:
        # Drain any stale frame, write, await the reply.
        while not self._inbox.empty():
            self._inbox.get_nowait()
        await self._client.write_gatt_char(self._uuid, data, response=True)
        return await asyncio.wait_for(self._inbox.get(), timeout=RECV_TIMEOUT)

    async def hello(self) -> bytes:
        return await self.send(bytes([tc.MSG_HELLO]))


# ─────────────────────────────────────────────────────────────────────────────
# A. Unpaired client
# ─────────────────────────────────────────────────────────────────────────────
async def check_unpaired_client(mac, uuid, token_id):
    print("\n[A] Unpaired client")
    async with Link(mac, uuid) as link:
        # A.1 — REQUEST with no prior HELLO: no challenge is active.
        bogus = bytes([tc.MSG_REQUEST]) + os.urandom(
            tc.NONCE_LEN + tc.IV_LEN + (1 + tc.HASH_LEN) + tc.TAG_LEN)
        reply = await link.send(bogus)
        code = err_code(reply)
        record("A.1 request before HELLO is refused (NO_CHALLENGE)",
               code == 0x02, f"token returned 0x{code:02X}" if code else f"{reply[:1]!r}")

        # A.2 — valid framing, but sealed with an auth key the client was never given.
        challenge = await link.hello()
        token_nonce = challenge[1:1 + tc.NONCE_LEN]
        wrong_key = os.urandom(32)
        request, _sk = tc.build_request(wrong_key, token_id, token_nonce,
                                        tc.OP_DERIVE, bytes(tc.HASH_LEN))
        reply = await link.send(request)
        code = err_code(reply)
        record("A.2 request with wrong auth key is refused (AUTH_FAILED)",
               code == 0x03, f"token returned 0x{code:02X}" if code else f"{reply[:1]!r}")


# ─────────────────────────────────────────────────────────────────────────────
# B. Repeated request (uses the paired credentials to make one valid request)
# ─────────────────────────────────────────────────────────────────────────────
async def check_repeated_request(mac, uuid, auth_key, token_id):
    print("\n[B] Repeated request")
    async with Link(mac, uuid) as link:
        # Make one genuinely valid request and keep its bytes.
        challenge = await link.hello()
        token_nonce = tc.parse_challenge(challenge, token_id)
        valid_req, sk = tc.build_request(auth_key, token_id, token_nonce,
                                         tc.OP_PING, bytes(tc.HASH_LEN))
        good_reply = await link.send(valid_req)
        try:
            tc.parse_response(good_reply, sk, token_id)
            baseline_ok = True
        except tc.TokenError:
            baseline_ok = False
        record("B.0 the original request is genuinely valid (baseline)", baseline_ok)

        # B.1 — send the same bytes again with no fresh HELLO: the nonce was consumed.
        reply = await link.send(valid_req)
        code = err_code(reply)
        record("B.1 repeat without new challenge is refused (NO_CHALLENGE)",
               code == 0x02, f"token returned 0x{code:02X}" if code else "not an error frame")

        # B.2 — send the old request after a fresh challenge: session key mismatch.
        await link.hello()                      # new token nonce
        reply = await link.send(valid_req)
        code = err_code(reply)
        record("B.2 repeat against a fresh challenge is refused (AUTH_FAILED)",
               code == 0x03, f"token returned 0x{code:02X}" if code else "not an error frame")


# ─────────────────────────────────────────────────────────────────────────────
# C. Lockout after 5 failures
# ─────────────────────────────────────────────────────────────────────────────
async def check_lockout(mac, uuid, auth_key, token_id, wait_recovery=False):
    print("\n[C] 5-failure lockout")
    async with Link(mac, uuid) as link:
        # Reset the failure counter to a known state with one successful request.
        challenge = await link.hello()
        token_nonce = tc.parse_challenge(challenge, token_id)
        req, sk = tc.build_request(auth_key, token_id, token_nonce,
                                   tc.OP_PING, bytes(tc.HASH_LEN))
        tc.parse_response(await link.send(req), sk, token_id)  # counter -> 0

        # Five bad requests, each with a fresh challenge.
        got_auth_fail = 0
        for i in range(5):
            challenge = await link.hello()
            # If the token locks mid-way, HELLO itself starts returning LOCKED_OUT.
            if err_code(challenge) == 0x05:
                break
            tnonce = challenge[1:1 + tc.NONCE_LEN]
            bad, _ = tc.build_request(os.urandom(32), token_id, tnonce,
                                      tc.OP_DERIVE, bytes(tc.HASH_LEN))
            reply = await link.send(bad)
            if err_code(reply) == 0x03:
                got_auth_fail += 1
        record("C.1 five bad requests each rejected (AUTH_FAILED)", got_auth_fail == 5,
               f"{got_auth_fail}/5 rejected")

        # The next message must now be refused outright.
        reply = await link.hello()
        code = err_code(reply)
        record("C.2 token is locked after 5 failures (LOCKED_OUT)",
               code == 0x05, f"token returned 0x{code:02X}" if code else "not an error frame")

        if wait_recovery:
            print("  [i] Waiting 31 s for the lockout to clear…")
            await asyncio.sleep(31)
            challenge = await link.hello()
            token_nonce = tc.parse_challenge(challenge, token_id)
            req, sk = tc.build_request(auth_key, token_id, token_nonce,
                                       tc.OP_PING, bytes(tc.HASH_LEN))
            try:
                tc.parse_response(await link.send(req), sk, token_id)
                recovered = True
            except tc.TokenError:
                recovered = False
            record("C.3 token recovers after the 30 s lockout window", recovered)


async def run_all(wait_recovery: bool):
    cfg, auth_key, token_id = tc._load_credentials()   # raises if this PC is not paired
    mac = cfg["ble_mac"]
    uuid = cfg.get("char_uuid", tc.CHARACTERISTIC_UUID)
    print(f"Target token {tc.token_fingerprint(token_id.hex())} at BLE {mac}")

    await check_unpaired_client(mac, uuid, token_id)
    await check_repeated_request(mac, uuid, auth_key, token_id)
    await check_lockout(mac, uuid, auth_key, token_id, wait_recovery)


def main():
    ap = argparse.ArgumentParser(description="Security verification of the 3T token over BLE.")
    ap.add_argument("--pair", metavar="COM_PORT",
                    help="Pair over USB first (e.g. --pair COM3), then run the checks.")
    ap.add_argument("--wait-recovery", action="store_true",
                    help="After the lockout check, wait 31 s and confirm the token recovers.")
    args = ap.parse_args()

    if args.pair:
        print(f"[i] Pairing over USB on {args.pair} …")
        ok, msg = tc.pair_token_usb(args.pair)
        print(f"    {'OK' if ok else 'FAILED'}: {msg}")
        if not ok:
            return 2

    if tc.load_config() is None:
        print("This PC is not paired with a token. Run with --pair COM3 first "
              "(the token must be plugged in over USB).")
        return 2

    try:
        asyncio.run(run_all(args.wait_recovery))
    except tc.TokenError as e:
        print(f"\n[!] Could not complete the run: {e}")
        return 2

    print("\n" + "=" * 60)
    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, _ in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    all_ok = passed == len(results)
    print(f"\n[{'PASS' if all_ok else 'FAIL'}] {passed}/{len(results)} checks passed — "
          + ("all token defences held." if all_ok else "SOME DEFENCES DID NOT HOLD."))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
