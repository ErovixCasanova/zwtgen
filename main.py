#!/usr/bin/env python3
"""
gen.py — Guest account generator (colorful, single + mass, thread pool)

Usage:
  python3 gen.py                     # interactive menu
  python3 gen.py --count 10          # mass gen 10 accounts
  python3 gen.py --count 10 --threads 5
  python3 gen.py --single            # one account
  python3 gen.py --region IND --count 5

Saves to GUEST_GEN/gen.json
"""

import os
import sys
import json
import hmac
import hashlib
import random
import string
import time
import codecs
import base64
import socket
import argparse
import threading
import queue
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ------------------------------------------------------------------
# ANSI colors
# ------------------------------------------------------------------
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

    BG_GREEN  = "\033[42m"
    BG_RED    = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"


def ok(msg):   print(f"{C.GREEN}[+]{C.RESET} {msg}")
def err(msg):  print(f"{C.RED}[-]{C.RESET} {msg}")
def info(msg): print(f"{C.CYAN}[*]{C.RESET} {msg}")
def warn(msg): print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def step(msg): print(f"{C.MAGENTA}[>]{C.RESET} {C.BOLD}{msg}{C.RESET}")


# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
KEY_HMAC = b"2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

OB_VERSION   = "OB55"
MREG_HOST    = "loginbp.ppmainecoonghj.com"
MREG_URL     = f"https://{MREG_HOST}/MajorRegister"
MLOGIN_URL   = f"https://{MREG_HOST}/MajorLogin"

GLD_HOSTS = {
    "IND": "client.ind.freefiremobile.com",
    "SG":  "clientbp.ggblueshark.com",
    "ID":  "clientbp.ggblueshark.com",
    "VN":  "clientbp.ggblueshark.com",
    "TH":  "clientbp.common.ggbluefox.com",
    "ME":  "clientbp.common.ggbluefox.com",
    "RU":  "clientbp.ggblueshark.com",
    "BD":  "clientbp.ggblueshark.com",
    "PK":  "clientbp.ggblueshark.com",
    "EU":  "clientbp.ggblueshark.com",
    "TW":  "clientbp.ggblueshark.com",
    "NA":  "client.us.freefiremobile.com",
    "SAC": "client.us.freefiremobile.com",
    "BR":  "client.us.freefiremobile.com",
}

GLD_FALLBACKS = [
    "client.ind.freefiremobile.com",
    "clientbp.ggblueshark.com",
    "clientbp.common.ggbluefox.com",
    "client.us.freefiremobile.com",
]

UA_MSDK  = "GarenaMSDK/4.0.44(V2437 ;Android 15;en;US;app 2.133.1 2019118527;)"
UA_UNITY = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"

OUT_DIR  = "GUEST_GEN"
OUT_FILE = os.path.join(OUT_DIR, "gen.json")


# ------------------------------------------------------------------
# Thread-safe storage
# ------------------------------------------------------------------
FILE_LOCK = threading.Lock()


def ensure_out_dir():
    os.makedirs(OUT_DIR, exist_ok=True)


def load_existing_accounts() -> list:
    ensure_out_dir()
    if not os.path.exists(OUT_FILE):
        return []
    try:
        with open(OUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_account(entry: dict):
    with FILE_LOCK:
        accounts = load_existing_accounts()
        uid = str(entry.get("uid", ""))
        existing = {str(a.get("uid", "")) for a in accounts}

        if uid and uid in existing:
            for i, a in enumerate(accounts):
                if str(a.get("uid", "")) == uid:
                    accounts[i] = entry
                    break
        else:
            accounts.append(entry)

        with open(OUT_FILE, "w", encoding="utf-8") as f:
            json.dump(accounts, f, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------
# DNS helpers
# ------------------------------------------------------------------
def host_resolves(host: str, timeout: float = 2.0) -> bool:
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(host)
        return True
    except Exception:
        return False


def pick_gld_host(region: str) -> str:
    primary = GLD_HOSTS.get(region.upper(), "clientbp.ggblueshark.com")
    candidates = [primary] + [h for h in GLD_FALLBACKS if h != primary]
    for h in candidates:
        if host_resolves(h):
            return h
    return primary


# ------------------------------------------------------------------
# Crypto
# ------------------------------------------------------------------
def aes_encrypt(raw: bytes) -> bytes:
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(raw, 16))


def encode_field14(open_id: str) -> bytes:
    ks = [
        0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31,
        0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30,
    ]
    enc = "".join(
        chr(ord(open_id[i]) ^ ks[i % len(ks)]) for i in range(len(open_id))
    )
    esc = "".join(c if 32 <= ord(c) <= 126 else f"\\u{ord(c):04x}" for c in enc)
    return codecs.decode(esc, "unicode_escape").encode("latin1")


# ------------------------------------------------------------------
# Protobuf writer
# ------------------------------------------------------------------
def enc_varint(n: int) -> bytes:
    out = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            break
    return bytes(out)


def pb(field: int, value) -> bytes:
    if isinstance(value, int):
        return enc_varint((field << 3) | 0) + enc_varint(value)
    if isinstance(value, (str, bytes)):
        v = value.encode() if isinstance(value, str) else value
        return enc_varint((field << 3) | 2) + enc_varint(len(v)) + v
    raise TypeError(f"unsupported field type: {type(value)}")


def build_proto(fields: dict) -> bytes:
    return b"".join(pb(k, v) for k, v in fields.items())


# ------------------------------------------------------------------
# Generators
# ------------------------------------------------------------------
def gen_username() -> str:
    """Obscura + 5 digits = 12 chars (fits 3-14)."""
    return f"Obscura{random.randint(10000, 99999)}"


def gen_password() -> str:
    """OBSCURACODER_ + 5 digits."""
    return f"OBSCURACODER_{random.randint(10000, 99999)}"


# ------------------------------------------------------------------
# HTTP session (per-thread)
# ------------------------------------------------------------------
_thread_local = threading.local()


def get_session() -> requests.Session:
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.verify = False
        s.headers.update({"Accept-Encoding": "gzip, deflate"})
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=64, pool_maxsize=128, max_retries=0
        )
        s.mount("https://", adapter)
        _thread_local.session = s
    return _thread_local.session


# ------------------------------------------------------------------
# Step 1 — guest register
# ------------------------------------------------------------------
def guest_register(password: str) -> int:
    s = get_session()
    payload = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(KEY_HMAC, body.encode(), hashlib.sha256).hexdigest()

    headers = {
        "Host": "ffmconnect.live.gop.garenanow.com",
        "User-Agent": UA_MSDK,
        "Authorization": f"Signature {sig}",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Connection": "Keep-Alive",
    }

    r = s.post(
        "https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest:register",
        headers=headers, data=body, timeout=15,
    )
    r.raise_for_status()
    return r.json()["data"]["uid"]


# ------------------------------------------------------------------
# Step 2 — token grant
# ------------------------------------------------------------------
def token_grant(uid: int, password: str) -> dict:
    s = get_session()
    payload = {
        "client_id": 100067,
        "client_secret": KEY_HMAC.decode(),
        "client_type": 2,
        "device_id": "",
        "password": password,
        "response_type": "token",
        "uid": uid,
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)

    headers = {
        "Host": "ffmconnect.live.gop.garenanow.com",
        "User-Agent": UA_MSDK,
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Connection": "Keep-Alive",
    }

    r = s.post(
        "https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest/token:grant",
        headers=headers, data=body, timeout=15,
    )
    r.raise_for_status()
    return r.json()["data"]


# ------------------------------------------------------------------
# Step 3 — MajorRegister
# ------------------------------------------------------------------
def major_register(access_token: str, open_id: str, username: str) -> requests.Response:
    s = get_session()
    field14 = encode_field14(open_id)

    payload = {
        1: username,
        2: access_token,
        3: open_id,
        5: 102000007,
        6: 4,
        7: 1,
        13: 1,
        14: field14,
        15: "en",
        16: 1,
        17: 1,
    }

    raw = build_proto(payload)
    enc = aes_encrypt(raw)

    headers = {
        "Host": MREG_HOST,
        "User-Agent": UA_UNITY,
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer",
        "X-GA": "v1 1",
        "ReleaseVersion": OB_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "Connection": "Keep-Alive",
    }

    return s.post(MREG_URL, headers=headers, data=enc, timeout=20)


# ------------------------------------------------------------------
# Step 4 — MajorLogin
# ------------------------------------------------------------------
MAJOR_LOGIN_TEMPLATE = (
    b'\x1a\x13' + b'2026-09-22 22:07:55' +
    b'"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)'
    b'J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300'
    b'z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2'
    b'\x80\x01\xc9\x0f'
    b'\x8a\x01\x0fAdreno (TM) 640'
    b'\x92\x01\rOpenGL ES 3.2'
    b'\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f'
    b'\xa2\x01\x0e105.235.139.91'
    b'\xaa\x01\x02en'
    b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d'
    b'\xba\x01\x014'
    b'\xc2\x01\x08Handheld'
    b'\xca\x01\x10Asus ASUS_I005DA'
    b'\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390'
    b'\xf0\x01\x01'
    b'\xca\x02\nATM Mobils'
    b'\xd2\x02\x04WIFI'
    b'\xca\x03 7428b253defc164018c604a1ebbfebdf'
    b'\xe0\x03\xa8\x81\x02'
    b'\xe8\x03\xf6\xe5\x01'
    b'\xf0\x03\xaf\x13'
    b'\xf8\x03\x84\x07'
    b'\x80\x04\xe7\xf0\x01'
    b'\x88\x04\xa8\x81\x02'
    b'\x90\x04\xe7\xf0\x01'
    b'\x98\x04\xa8\x81\x02'
    b'\xc8\x04\x01'
    b'\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm'
    b'\xe0\x04\x01'
    b'\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|'
    b'/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk'
    b'\xf0\x04\x03'
    b'\xf8\x04\x01'
    b'\x8a\x05\x0232'
    b'\x9a\x05\n2019118692'
    b'\xb2\x05\tOpenGLES2'
    b'\xb8\x05\xff\x7f'
    b'\xc0\x05\x04'
    b'\xe0\x05\xf3F'
    b'\xea\x05\x07android'
    b'\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2'
    b'\xf8\x05\xfb\xe4\x06'
    b'\x88\x06\x01'
    b'\x90\x06\x01'
    b'\x9a\x06\x014'
    b'\xa2\x06\x014'
    b'\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
)


def major_login(access_token: str, open_id: str) -> requests.Response:
    s = get_session()
    data = MAJOR_LOGIN_TEMPLATE
    data = data.replace(
        b"afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390",
        access_token.encode()[:64].ljust(64, b"0"),
    )
    data = data.replace(
        b"1d8ec0240ede109973f3321b9354b44d",
        open_id.encode()[:32].ljust(32, b"0"),
    )

    enc = aes_encrypt(data)

    headers = {
        "Host": MREG_HOST,
        "User-Agent": UA_UNITY,
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer",
        "X-GA": "v1 1",
        "ReleaseVersion": OB_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "Connection": "Keep-Alive",
    }

    return s.post(MLOGIN_URL, headers=headers, data=enc, timeout=20)


# ------------------------------------------------------------------
# Step 5 — GetLoginData
# ------------------------------------------------------------------
def get_login_data(jwt_token: str, region: str = "IND") -> requests.Response:
    s = get_session()
    host = pick_gld_host(region)
    url  = f"https://{host}/GetLoginData"

    payload = (
        b':\x072.133.7'
        b'\xaa\x01\x02en'
        b'\x9a\x05\n2019118527'
    )
    enc = aes_encrypt(payload)

    headers = {
        "Host": host,
        "User-Agent": UA_UNITY,
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {jwt_token}",
        "X-GA": "v1 1",
        "ReleaseVersion": OB_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "Connection": "Keep-Alive",
    }

    return s.post(url, headers=headers, data=enc, timeout=25)


# ------------------------------------------------------------------
# JWT helpers
# ------------------------------------------------------------------
def extract_jwt(text: str) -> str:
    idx = text.find("eyJ")
    if idx == -1:
        return ""
    tok = text[idx:]
    dot2 = tok.find(".", tok.find(".") + 1)
    if dot2 != -1:
        tok = tok[:dot2 + 44]
    return tok


def decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64).decode())
    except Exception:
        return {}


# ------------------------------------------------------------------
# Single-account flow
# ------------------------------------------------------------------
def create_one_account(verbose: bool = True) -> dict:
    password = gen_password()
    username = gen_username()

    entry = {
        "username":    username,
        "uid":         None,
        "password":    password,
        "region":      None,
        "open_id":     None,
        "access_token": None,
        "jwt_token":   None,
        "created_at":  datetime.now(timezone.utc).isoformat(),
        "status":      "pending",
    }

    try:
        if verbose: step(f"register {username}")
        uid = guest_register(password)
        entry["uid"] = uid
        if verbose: ok(f"uid = {C.YELLOW}{uid}{C.RESET}")

        if verbose: step(f"token grant")
        tok = token_grant(uid, password)
        entry["open_id"]      = tok["open_id"]
        entry["access_token"] = tok["access_token"]
        if verbose: ok(f"open_id = {entry['open_id'][:16]}...")

        if verbose: step(f"MajorRegister")
        r = major_register(entry["access_token"], entry["open_id"], username)
        if r.status_code != 200:
            entry["status"] = f"major_register_{r.status_code}"
            save_account(entry)
            if verbose: err(f"MajorRegister HTTP {r.status_code} — saved with status")
            return entry
        if verbose: ok(f"MajorRegister HTTP 200")

        if verbose: step(f"MajorLogin")
        lr = major_login(entry["access_token"], entry["open_id"])
        jwt_token = ""
        try:
            jwt_token = extract_jwt(lr.content.decode(errors="ignore"))
        except Exception:
            pass

        if not jwt_token:
            entry["status"] = "major_login_no_jwt"
            save_account(entry)
            if verbose: err(f"MajorLogin HTTP {lr.status_code} — no JWT")
            return entry

        entry["jwt_token"] = jwt_token

        payload = decode_jwt_payload(jwt_token)
        region = payload.get("noti_region") or payload.get("lock_region") or "IND"
        entry["region"] = region
        if verbose: ok(f"JWT acquired — region {region}")

        if verbose: step(f"GetLoginData")
        try:
            gr = get_login_data(jwt_token, region)
            if gr.status_code == 200:
                entry["status"] = "complete"
                if verbose: ok(f"GetLoginData HTTP 200")
            else:
                entry["status"] = f"gld_{gr.status_code}"
                if verbose: warn(f"GetLoginData HTTP {gr.status_code}")
        except requests.exceptions.RequestException as e:
            entry["status"] = "gld_failed_but_valid"
            if verbose: warn(f"GetLoginData network error — account still valid")

        save_account(entry)
        if verbose: ok(f"saved -> {OUT_FILE}")
        return entry

    except Exception as e:
        entry["status"] = f"error_{type(e).__name__}"
        entry["error"]  = str(e)
        save_account(entry)
        if verbose: err(f"fatal: {e}")
        return entry


# ------------------------------------------------------------------
# Mass-gen (thread pool)
# ------------------------------------------------------------------
class Counter:
    def __init__(self):
        self.lock = threading.Lock()
        self.ok = 0
        self.fail = 0
        self.total = 0

    def add_ok(self):
        with self.lock: self.ok += 1

    def add_fail(self):
        with self.lock: self.fail += 1

    def snapshot(self):
        with self.lock:
            return self.ok, self.fail, self.total


def mass_gen(count: int, threads: int, region: str = "IND"):
    info(f"mass gen: {count} accounts, {threads} threads")
    info(f"output: {OUT_FILE}")
    print()

    counter = Counter()
    counter.total = count
    start = time.time()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(create_one_account, False): i for i in range(count)}

        for fut in as_completed(futures):
            try:
                entry = fut.result()
                if entry.get("status") == "complete":
                    counter.add_ok()
                    ok(f"{entry['username']} | uid={entry['uid']} | region={entry['region']}")
                else:
                    counter.add_fail()
                    warn(f"{entry['username']} | uid={entry['uid']} | status={entry['status']}")
            except Exception as e:
                counter.add_fail()
                err(f"thread error: {e}")

    elapsed = time.time() - start
    done_ok, done_fail, _ = counter.snapshot()
    print()
    print(f"{C.CYAN}{'='*60}{C.RESET}")
    print(f"{C.BOLD}MASS GEN SUMMARY{C.RESET}")
    print(f"{C.CYAN}{'='*60}{C.RESET}")
    print(f"  {C.GREEN}complete : {done_ok}{C.RESET}")
    print(f"  {C.RED}failed   : {done_fail}{C.RESET}")
    print(f"  total    : {done_ok + done_fail}/{count}")
    print(f"  elapsed  : {elapsed:.2f}s")
    print(f"  speed    : {(done_ok + done_fail) / elapsed:.2f} acc/s")
    print(f"  saved to : {OUT_FILE}")
    print(f"{C.CYAN}{'='*60}{C.RESET}")


# ------------------------------------------------------------------
# Menu
# ------------------------------------------------------------------
def banner():
    print(f"{C.CYAN}{'═' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}        OBSCURA GUEST ACCOUNT GENERATOR{C.RESET}")
    print(f"{C.CYAN}{'═' * 60}{C.RESET}")
    print(f"  {C.YELLOW}Version :{C.RESET} {OB_VERSION}")
    print(f"  {C.YELLOW}Host    :{C.RESET} {MREG_HOST}")
    print(f"  {C.YELLOW}Output  :{C.RESET} {OUT_FILE}")
    print(f"{C.CYAN}{'═' * 60}{C.RESET}")
    print()


def menu():
    banner()
    print(f"  {C.GREEN}1){C.RESET} Single account")
    print(f"  {C.GREEN}2){C.RESET} Mass gen")
    print(f"  {C.GREEN}3){C.RESET} Show stats")
    print(f"  {C.GREEN}0){C.RESET} Exit")
    print()

    try:
        choice = input(f"{C.CYAN}>{C.RESET} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if choice == "1":
        print()
        create_one_account(verbose=True)
        print()
        input(f"{C.DIM}Press Enter to return...{C.RESET}")
        menu()

    elif choice == "2":
        try:
            count   = int(input(f"{C.CYAN}How many?{C.RESET} ").strip() or "10")
            threads = int(input(f"{C.CYAN}Threads?{C.RESET} ").strip() or "5")
        except ValueError:
            err("invalid input")
            return
        print()
        mass_gen(count, threads)
        print()
        input(f"{C.DIM}Press Enter to return...{C.RESET}")
        menu()

    elif choice == "3":
        accounts = load_existing_accounts()
        total = len(accounts)
        complete = sum(1 for a in accounts if a.get("status") == "complete")
        failed = total - complete
        print()
        print(f"{C.CYAN}{'='*60}{C.RESET}")
        print(f"{C.BOLD}STATS{C.RESET}")
        print(f"{C.CYAN}{'='*60}{C.RESET}")
        print(f"  total    : {total}")
        print(f"  complete : {C.GREEN}{complete}{C.RESET}")
        print(f"  failed   : {C.RED}{failed}{C.RESET}")
        print(f"  file     : {OUT_FILE}")
        print(f"{C.CYAN}{'='*60}{C.RESET}")
        print()
        input(f"{C.DIM}Press Enter to return...{C.RESET}")
        menu()

    elif choice == "0":
        info("bye")
        sys.exit(0)

    else:
        err("invalid choice")
        time.sleep(0.5)
        menu()


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Obscura guest gen")
    p.add_argument("--count",   type=int, default=0, help="number of accounts (0 = interactive)")
    p.add_argument("--threads", type=int, default=5, help="threads for mass gen")
    p.add_argument("--region",  type=str, default="IND", help="region (IND/SG/ID/...)")
    p.add_argument("--single",  action="store_true", help="generate one account and exit")
    return p.parse_args()


def main():
    args = parse_args()

    if args.single:
        banner()
        create_one_account(verbose=True)
        return

    if args.count > 0:
        banner()
        mass_gen(args.count, args.threads, args.region)
        return

    try:
        menu()
    except KeyboardInterrupt:
        print()
        info("interrupted")
        sys.exit(0)


if __name__ == "__main__":
    main()
