"""One-shot smoke checks for the Compose `verify` service.

Waits for the app container's /health, then exercises the review page and
the verification API over HTTP.  Exits 0 when every check passes, 1 otherwise.
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from builder import (bad_return_address_class, legal_construction_class,  # noqa: E402
                     legacy_finally_class, nested_finally_class,
                     uninitialized_escape_class, wide_jsr_finally_class)

APP = os.environ.get("APP_URL", "http://app:8080").rstrip("/")

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not cond else ""),
          flush=True)
    if not cond:
        FAILURES.append(name)


def get(path):
    try:
        with urllib.request.urlopen(APP + path, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # connection refused etc.
        return None, str(e).encode()


def post(obj):
    req = urllib.request.Request(
        APP + "/api/verify", data=json.dumps(obj).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def wait_for_health():
    for _ in range(60):
        status, body = get("/health")
        if status == 200:
            return True
        time.sleep(0.5)
    return False


def main():
    print(f"smoke against {APP}", flush=True)
    check("health endpoint becomes ready", wait_for_health())

    status, body = get("/health")
    check("GET /health -> 200 {\"status\":\"ok\"}",
          status == 200 and json.loads(body) == {"status": "ok"},
          f"status={status} body={body!r}")

    status, body = get("/")
    check("GET / serves the review page",
          status == 200 and b"<textarea" in body and b"/api/verify" in body,
          f"status={status}")

    ok_class = base64.b64encode(legal_construction_class()).decode("ascii")
    status, res = post({"class_b64": ok_class})
    check("POST legal class -> ok=true with per-offset states",
          status == 200 and res.get("ok") is True and len(res.get("states", [])) > 0,
          f"status={status} res={res}")
    handler_ok = (res.get("handlers") and
                  res["handlers"][0]["stack"] == ["ref java/lang/Throwable"])
    check("handler entry state reported", bool(handler_ok),
          f"handlers={res.get('handlers')}")

    bad_class = base64.b64encode(uninitialized_escape_class()).decode("ascii")
    status, res = post({"class_b64": bad_class})
    err = res.get("error") or {}
    check("POST half-initialized class -> ok=false, first evidence at offset 4",
          status == 200 and res.get("ok") is False
          and err.get("kind") == "uninitialized-escapes-to-handler"
          and err.get("offset") == 4,
          f"status={status} res={res}")

    # --- Old-javac shared cleanup segments (jsr/jsr_w/ret) ----------------

    def state_map(r):
        return {s["offset"]: s for s in r.get("states", [])}

    legacy = base64.b64encode(legacy_finally_class()).decode("ascii")
    status, res = post({"class_b64": legacy})
    sm = state_map(res)
    key_offsets = all(off in sm and sm[off].get("reachable")
                      for off in (0, 5, 8, 9, 11, 13, 14))
    shared_ok = (status == 200 and res.get("ok") is True and key_offsets
                 and sm.get(9, {}).get("stack") == ["retaddr {@3, @8}"]
                 and sm.get(11, {}).get("insn") == "ret 1"
                 and (res.get("handlers") or [{}])[0].get("handler_pc") == 13
                 and (res.get("handlers") or [{}])[0].get("reachable") is True)
    check("POST legacy finally class -> ok=true; both call sites share the "
          "cleanup segment with states and adjacent handler",
          bool(shared_ok), f"status={status} res={res}")

    wide = base64.b64encode(wide_jsr_finally_class()).decode("ascii")
    status, res = post({"class_b64": wide})
    sm = state_map(res)
    wide_ok = (status == 200 and res.get("ok") is True
               and sm.get(0, {}).get("insn") == "jsr_w 126"
               and sm.get(126, {}).get("stack") == ["retaddr @5"]
               and sm.get(128, {}).get("insn") == "ret 0")
    check("POST wide jsr_w class -> ok=true with continuation state",
          bool(wide_ok), f"status={status} res={res}")

    nested = base64.b64encode(nested_finally_class()).decode("ascii")
    status, res = post({"class_b64": nested})
    sm = state_map(res)
    nested_ok = (status == 200 and res.get("ok") is True
                 and sm.get(10, {}).get("stack") == ["retaddr @8"]
                 and sm.get(12, {}).get("locals") ==
                 ["top", "retaddr @3", "retaddr @8"])
    check("POST nested cleanup class -> ok=true, both continuations tracked",
          bool(nested_ok), f"status={status} res={res}")

    bad_ret = base64.b64encode(bad_return_address_class()).decode("ascii")
    status, res = post({"class_b64": bad_ret})
    err = res.get("error") or {}
    check("POST illegal return-address class -> ok=false, bad-return-address "
          "at first accurate offset 2",
          status == 200 and res.get("ok") is False
          and err.get("kind") == "bad-return-address"
          and err.get("offset") == 2,
          f"status={status} res={res}")

    status, res = post({"class_b64": "###not-base64###"})
    check("invalid Base64 -> 400 invalid-base64",
          status == 400 and (res.get("error") or {}).get("kind") == "invalid-base64",
          f"status={status} res={res}")

    big = base64.b64encode(b"\x00" * 70000).decode("ascii")
    status, res = post({"class_b64": big})
    check("oversize class -> 400 class-too-large",
          status == 400 and (res.get("error") or {}).get("kind") == "class-too-large",
          f"status={status} res={res}")

    if FAILURES:
        print(f"SMOKE FAILED: {len(FAILURES)} check(s): {FAILURES}", flush=True)
        return 1
    print("SMOKE OK: all checks passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
