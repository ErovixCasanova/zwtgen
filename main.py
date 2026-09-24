#!/usr/bin/env python3
"""
JWT Generator — Flask API (full OB55 payload)
"""
import os, sys, json, base64, time
from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# SETTINGS
# ============================================================
MAIN_KEY_B64 = "WWcmdGMlREV1aDYlWmNeOA=="
MAIN_IV_B64  = "Nm95WkRyMjJFM3ljaGpNJQ=="

RELEASE_VERSION = os.environ.get("RELEASE_VERSION", "OB55")
X_UNITY_VERSION = os.environ.get("X_UNITY_VERSION", "2018.4.12f1")
TIMEOUT         = float(os.environ.get("TIMEOUT", "20"))

USER_AGENT     = os.environ.get("USER_AGENT",
                 "GarenaMSDK/4.0.19P10(I2404 ;Android 15;en;US;)")
MAJOR_LOGIN_UA = os.environ.get("MAJOR_LOGIN_UA",
                 "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)")

OAUTH_URL       = os.environ.get("OAUTH_URL",
                  "https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest/token:grant")
MAJOR_LOGIN_URL = os.environ.get("MAJOR_LOGIN_URL",
                  "https://loginbp.ppmainecoonghj.com/MajorLogin")

CLIENT_SECRET = os.environ.get("CLIENT_SECRET",
                "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3")
CLIENT_ID     = int(os.environ.get("CLIENT_ID", "100067"))

MAIN_KEY = base64.b64decode(MAIN_KEY_B64)
MAIN_IV  = base64.b64decode(MAIN_IV_B64)


# ============================================================
# CRYPTO
# ============================================================
def pkcs7_pad(b, block_size=16):
    pad_len = block_size - (len(b) % block_size)
    return b + bytes([pad_len]) * pad_len

def aes_cbc_encrypt(key, iv, plaintext):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(plaintext, 16))


# ============================================================
# MINIMAL PROTOBUF
# ============================================================
def _ev(n):
    o = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        o.append(b)
        if not n: break
    return bytes(o)

def _pb(field, value):
    if isinstance(value, int):
        return _ev((field << 3) | 0) + _ev(value)
    if isinstance(value, (str, bytes)):
        x = value.encode() if isinstance(value, str) else value
        return _ev((field << 3) | 2) + _ev(len(x)) + x
    raise TypeError(f"unsupported field type: {type(value)}")

def build_proto(fields):
    return b"".join(_pb(k, v) for k, v in fields.items())

def _rv(b, p):
    r = 0; s = 0
    while True:
        if p >= len(b): raise ValueError("trunc")
        x = b[p]; p += 1
        r |= (x & 0x7F) << s
        if not (x & 0x80): return r, p
        s += 7

def parse_proto(buf, depth=6):
    if depth < 0 or not buf: return {}
    out = {}; p = 0
    while p < len(buf):
        try: tag, p = _rv(buf, p)
        except ValueError: return out
        f, w = tag >> 3, tag & 7
        if w == 0:
            try: v, p = _rv(buf, p)
            except ValueError: return out
            out[f] = v
        elif w == 2:
            try: ln, p = _rv(buf, p)
            except ValueError: return out
            if p + ln > len(buf): return out
            chunk = buf[p:p+ln]; p += ln
            try:
                s = chunk.decode()
                if all(c.isprintable() or c in "\r\n\t" for c in s):
                    out[f] = s; continue
            except Exception: pass
            nested = parse_proto(chunk, depth - 1)
            out[f] = nested if nested else chunk.hex()
        elif w == 5:
            if p + 4 > len(buf): return out
            p += 4
        elif w == 1:
            if p + 8 > len(buf): return out
            p += 8
        else:
            return out
    return out


# ============================================================
# FULL MajorLogin PAYLOAD (matches your curl)
# ============================================================
def build_major_login_payload(access_token, open_id, region="IND"):
    """
    Full device-info payload for OB55 MajorLogin.
    Fields 22 (open_id) and 29 (access_token) are replaced with real values.
    """
    # device blob for field 14 (32 bytes) — can be anything plausible
    field14_blob = bytes.fromhex(
        "0009540054540602095507090454075654050755510b54050207540608520707"
    )

    payload = {
        3:  "2026-09-22 22:07:18",
        4:  "free fire",
        5:  1,
        7:  "2.133.7",
        8:  "Android OS 15 / API-35 (AP3A.240905.015.A2_CS_V000L1/compiler251017142707)",
        9:  "Handheld",
        11: "CarrierDataNetwork",
        12: 2408,
        13: 1080,
        14: "440",
        15: "ARM64 FP ASIMD AES | 2500 | 8",
        16: 7504,
        17: "Mali-G615 MC2",
        18: "OpenGL ES 3.2 v1.r44p1-01eac0.148b774f93332d7e562320793fb6c4c9",
        19: "Google|7c873f16-ff3b-48f3-8f8e-92122d566062",
        20: "152.58.163.52",
        21: "en",
        22: open_id,                                    # <-- REPLACED
        23: "4",
        24: "Handheld",
        25: "vivo V2437",
        26: region.upper()[:2] if region.upper() != "IND" else "SG",
        29: access_token,                               # <-- REPLACED
        30: 1,
        42: "5G",
        57: "ffd6314a83f267ac4f9407fd2e5a0480",
        60: 105897,
        61: 4202,
        62: 2764,
        64: 4726,
        65: 105897,
        66: 4726,
        67: 105897,
        73: 3,
        74: "/data/app/~~KAHvGuHZk2eTZWvRRuvmqw==/com.dts.freefiremax-A9syIbYLOB9ho9WBbOkp2w==/lib/arm64",
        76: 2,
        77: "38f4751a330688ab124c2c804cec90a5|/data/app/~~KAHvGuHZk2eTZWvRRuvmqw==/com.dts.freefiremax-A9syIbYLOB9ho9WBbOkp2w==/base.apk",
        78: 2,
        79: 2,
        81: "64",
        83: "2019118527",
        86: "OpenGLES3",
        87: 8191,
        88: 4,
        92: 32399,
        93: "android_max",
        94: "KqsHT9Va+Sp7YXoOOzXtc7P3EFt4tsDkTi9xUKxhBiW+PXRCw6V3cPQDCdXd0Kdh8yWZBhsgcCZeObtQuq7nauuusC4ZCbZfnRWf719ByTkilFU0",
        96: '{"cur_rate":[60,90,120],"support_etc2":true}',
        97: 1,
        98: 1,
        99: "4",
        100: "4",
        104: 76900,
        105: 1,
        106: "https://dl.cdn.freefiremobile.com/live/ABHotUpdates/|https://dl-core.cdn.freefiremobile.com/live/ABHotUpdates/|211c933168f55902c7dfbfd8c4e2957d",
        107: "c8e41b7a93f02d56e1a94c7b8203f5d1",
    }

    # serialize to protobuf bytes
    body = bytearray()
    for f, v in payload.items():
        body += _pb(f, v)

    # NOTE: field 14 in the original curl is a binary blob, not a string.
    # If your target host needs it, add it after the string fields:
    # body += _pb(14, field14_blob)

    return bytes(body)


# ============================================================
# HELPERS
# ============================================================
def find_jwt(obj):
    if isinstance(obj, str):
        i = obj.find("eyJ")
        if i != -1:
            t = obj[i:]
            d = t.find(".", t.find(".") + 1)
            return t[:d + 44] if d != -1 else t
    elif isinstance(obj, dict):
        for v in obj.values():
            r = find_jwt(v)
            if r: return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_jwt(v)
            if r: return r
    return ""

def decode_jwt_payload(jwt):
    try:
        p = jwt.split(".")[1]
        p += "=" * ((4 - len(p) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(p).decode())
    except Exception:
        return {}


# ============================================================
# OAUTH
# ============================================================
def get_access_token(uid, password):
    payload = {
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "client_type":   2,
        "password":      password,
        "response_type": "token",
        "uid":           int(uid),
    }
    headers = {
        "User-Agent":      USER_AGENT,
        "Accept":          "application/json",
        "Content-Type":    "application/json; charset=utf-8",
        "Connection":      "Keep-Alive",
        "Accept-Encoding": "gzip",
    }
    r = requests.post(OAUTH_URL, json=payload, headers=headers,
                      verify=False, timeout=TIMEOUT)
    r.raise_for_status()
    j = r.json()
    data = j.get("data", j)
    if "access_token" not in data or not data["access_token"]:
        raise RuntimeError(f"oauth error: {json.dumps(j)[:200]}")
    return data["access_token"], data["open_id"]


# ============================================================
# MAJOR LOGIN
# ============================================================
def major_login(open_id, access_token, region="IND"):
    req = build_major_login_payload(access_token, open_id, region)
    encrypted = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, req)

    headers = {
        "Host":             "loginbp.ppmainecoonghj.com",
        "User-Agent":       MAJOR_LOGIN_UA,
        "Accept":           "*/*",
        "Accept-Encoding":  "deflate, gzip",
        "X-GA-SV":          str(int(time.time())),
        "Authorization":    "Bearer",
        "X-GA":             "v1 1",
        "ReleaseVersion":   RELEASE_VERSION,
        "Content-Type":     "application/x-www-form-urlencoded",
        "X-Unity-Version":  X_UNITY_VERSION,
    }

    r = requests.post(MAJOR_LOGIN_URL, data=encrypted, headers=headers,
                      verify=False, timeout=TIMEOUT)

    # ---- verbose diagnostics ----
    print(f"[DEBUG] HTTP {r.status_code}")
    print(f"[DEBUG] response headers: {dict(r.headers)}")
    print(f"[DEBUG] response len: {len(r.content)}")
    print(f"[DEBUG] response hex (first 200): {r.content[:200].hex()}")
    try:
        decoded = parse_proto(r.content)
        print(f"[DEBUG] decoded: {json.dumps(decoded, default=str)[:500]}")
    except Exception as e:
        print(f"[DEBUG] decode failed: {e}")
        print(f"[DEBUG] raw ascii: {r.content.decode('utf-8', errors='ignore')[:200]!r}")
    # ---- end verbose ----

    if r.status_code != 200:
        try:
            decoded = parse_proto(r.content)
            detail = json.dumps(decoded, default=str)[:300]
        except Exception:
            detail = r.content.hex()[:200]
        raise RuntimeError(f"MajorLogin HTTP {r.status_code} — {detail}")

    decoded = parse_proto(r.content)
    jwt = find_jwt(decoded)
    if not jwt:
        raise RuntimeError(
            f"no JWT in response — decoded={json.dumps(decoded, default=str)[:300]}"
        )
    return jwt


# ============================================================
# FLASK
# ============================================================
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "JWT Generator",
        "version": "1.0",
        "endpoints": {
            "GET  /health":             "health check",
            "GET  /api/jwt":            "uid + password (query)",
            "POST /api/jwt":            "body: {uid, password, region?}",
            "POST /api/jwt/from-token": "body: {access_token, open_id, region?}",
        },
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": int(time.time())})


@app.route("/api/jwt", methods=["GET", "POST", "OPTIONS"])
def api_jwt():
    if request.method == "OPTIONS":
        return "", 204

    if request.method == "GET":
        uid      = request.args.get("uid")
        password = request.args.get("password")
        region   = request.args.get("region", "IND")
    else:
        body     = request.get_json(silent=True) or {}
        uid      = body.get("uid")
        password = body.get("password")
        region   = body.get("region", "IND")

    if not uid or not password:
        return jsonify({"error": "uid and password required"}), 400

    try:
        access_token, open_id = get_access_token(str(uid), str(password))
        jwt = major_login(open_id, access_token, region)
        pl  = decode_jwt_payload(jwt)
        return jsonify({
            "success":      True,
            "access_token": access_token,
            "open_id":      open_id,
            "jwt":          jwt,
            "region":       pl.get("noti_region") or pl.get("lock_region"),
            "account_id":   pl.get("account_id"),
            "nickname":     pl.get("nickname"),
            "is_emulator":  pl.get("is_emulator"),
            "expires_at":   pl.get("exp"),
        })
    except requests.exceptions.HTTPError as e:
        return jsonify({
            "error": "HTTP error",
            "status": e.response.status_code if e.response is not None else 0,
            "detail": str(e),
        }), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/jwt/from-token", methods=["POST", "OPTIONS"])
def api_jwt_from_token():
    if request.method == "OPTIONS":
        return "", 204

    body = request.get_json(silent=True) or {}
    access_token = body.get("access_token")
    open_id      = body.get("open_id")
    region       = body.get("region", "IND")

    if not access_token or not open_id:
        return jsonify({"error": "access_token and open_id required"}), 400

    try:
        jwt = major_login(str(open_id), str(access_token), region)
        pl  = decode_jwt_payload(jwt)
        return jsonify({
            "success":      True,
            "access_token": access_token,
            "open_id":      open_id,
            "jwt":          jwt,
            "region":       pl.get("noti_region") or pl.get("lock_region"),
            "account_id":   pl.get("account_id"),
            "nickname":     pl.get("nickname"),
            "is_emulator":  pl.get("is_emulator"),
            "expires_at":   pl.get("exp"),
        })
    except requests.exceptions.HTTPError as e:
        return jsonify({
            "error": "HTTP error",
            "status": e.response.status_code if e.response is not None else 0,
            "detail": str(e),
        }), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found", "path": request.path}), 404


@app.errorhandler(500)
def server_err(e):
    return jsonify({"error": "internal server error"}), 500


if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", "8000"))
    print(f"[*] JWT Generator API on http://0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
