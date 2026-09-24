#!/usr/bin/env python3
"""
jwt_api.py — Flask JWT generator (single file)

Endpoints:
  GET  /                     → info
  GET  /health               → health check
  POST /api/jwt              → generate JWT from uid + password
  POST /api/jwt/from-token   → generate JWT from access_token + open_id
  GET  /api/jwt              → same as POST but via query params

Run:
  pip install flask requests pycryptodome
  python3 jwt_api.py
"""
import os, sys, json, base64, time, codecs
from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Suppress InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# SETTINGS
# ============================================================
class Settings:
    MAIN_KEY_B64 = "WWcmdGMlREV1aDYlWmNeOA=="
    MAIN_IV_B64  = "Nm95WkRyMjJFM3ljaGpNJQ=="

    RELEASE_VERSION = "OB55"
    X_UNITY_VERSION = "2018.4.11f1"
    TIMEOUT         = 15.0

    USER_AGENT     = "GarenaMSDK/4.0.19P10(I2404 ;Android 15;en;US;)"
    MAJOR_LOGIN_UA = ("Dalvik/2.1.0 (Linux; U; Android 15; I2404 "
                      "Build/AP3A.240905.015.A2_V000L1)")

    OAUTH_URL       = "https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest/token:grant"
    MAJOR_LOGIN_URL = "https://loginbp.ggwhitehawk.com/MajorLogin"

    CLIENT_SECRET   = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
    CLIENT_ID       = 100067

    @property
    def MAIN_KEY(self) -> bytes:
        return base64.b64decode(self.MAIN_KEY_B64)

    @property
    def MAIN_IV(self) -> bytes:
        return base64.b64decode(self.MAIN_IV_B64)


settings = Settings()


# ============================================================
# CRYPTO
# ============================================================
def pkcs7_pad(b: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(b) % block_size)
    return b + bytes([pad_len]) * pad_len


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(plaintext, 16))


# ============================================================
# MINIMAL PROTOBUF  (no .proto files)
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
    """Walk a protobuf message; returns dict {field: value}."""
    if depth < 0 or not buf:
        return {}
    out = {}
    p = 0
    while p < len(buf):
        try:
            tag, p = _rv(buf, p)
        except ValueError:
            return out
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
            except Exception:
                pass
            nested = parse_proto(chunk, depth - 1)
            if nested:
                out[f] = nested
            else:
                out[f] = chunk.hex()
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
# LoginReq protobuf (fields from LoginReq.proto)
# ============================================================
def build_login_req(open_id: str, open_id_type: str, login_token: str,
                    origin_platform_type: str) -> bytes:
    """
    message LoginReq {
      string open_id                = 1;
      string open_id_type           = 2;
      string login_token            = 3;
      string orign_platform_type    = 4;
    }
    """
    return build_proto({
        1: open_id,
        2: open_id_type,
        3: login_token,
        4: origin_platform_type,
    })


# ============================================================
# OAUTH  — uid + password → access_token + open_id
# ============================================================
def get_access_token(uid: str, password: str):
    payload = {
        "client_id":     settings.CLIENT_ID,
        "client_secret": settings.CLIENT_SECRET,
        "client_type":   2,
        "password":      password,
        "response_type": "token",
        "uid":           int(uid),
    }
    headers = {
        "User-Agent":     settings.USER_AGENT,
        "Accept":         "application/json",
        "Content-Type":   "application/json; charset=utf-8",
        "Connection":     "Keep-Alive",
        "Accept-Encoding": "gzip",
    }
    r = requests.post(settings.OAUTH_URL, json=payload,
                      headers=headers, verify=False, timeout=settings.TIMEOUT)
    r.raise_for_status()

    j = r.json()
    data = j.get("data", j)

    if "access_token" not in data or not data["access_token"]:
        raise RuntimeError(f"oauth error: {json.dumps(j)[:200]}")

    return data["access_token"], data["open_id"]


# ============================================================
# MAJOR LOGIN  — LoginReq → JWT
# ============================================================
def major_login(open_id: str, access_token: str) -> dict:
    req = build_login_req(
        open_id=open_id,
        open_id_type="4",
        login_token=access_token,
        origin_platform_type="4",
    )
    encrypted = aes_cbc_encrypt(settings.MAIN_KEY, settings.MAIN_IV, req)

    headers = {
        "User-Agent":      settings.MAJOR_LOGIN_UA,
        "Connection":      "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type":    "application/octet-stream",
        "Expect":          "100-continue",
        "X-Unity-Version": settings.X_UNITY_VERSION,
        "X-GA":            "v1 1",
        "ReleaseVersion":  settings.RELEASE_VERSION,
    }

    r = requests.post(settings.MAJOR_LOGIN_URL, data=encrypted,
                      headers=headers, verify=False, timeout=settings.TIMEOUT)
    r.raise_for_status()

    # Response is raw protobuf bytes (LoginRes)
    decoded = parse_proto(r.content)

    # LoginRes fields (from FreeFire.proto):
    #   token          = 6  (or 3, depending on build)
    #   lock_region    = 4
    #   server_url     = ?
    # We'll scan for a JWT-looking string anywhere in the decoded tree.
    jwt = _find_jwt(decoded)

    if not jwt:
        raise RuntimeError(f"no JWT in response — decoded={json.dumps(decoded, default=str)[:300]}")

    return {
        "token":      jwt,
        "lockRegion": _find_field(decoded, ["lock_region", "lockRegion"]) or _find_region(jwt),
        "serverUrl":  _find_field(decoded, ["server_url", "serverUrl"]) or "",
    }


def _find_jwt(obj):
    """Recursively hunt for a JWT (eyJ...) inside parsed protobuf."""
    if isinstance(obj, str):
        i = obj.find("eyJ")
        if i != -1:
            t = obj[i:]
            d = t.find(".", t.find(".") + 1)
            return t[:d + 44] if d != -1 else t
    elif isinstance(obj, dict):
        for v in obj.values():
            r = _find_jwt(v)
            if r: return r
    elif isinstance(obj, list):
        for v in obj:
            r = _find_jwt(v)
            if r: return r
    return ""


def _find_field(obj, names):
    """Best-effort: return first value whose key matches one of names (case-insensitive)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in [n.lower() for n in names]:
                return v
            r = _find_field(v, names)
            if r: return r
    return ""


def _find_region(jwt: str) -> str:
    """Decode JWT payload to get region from claim."""
    try:
        p = jwt.split(".")[1]
        p += "=" * ((4 - len(p) % 4) % 4)
        pl = json.loads(base64.urlsafe_b64decode(p).decode())
        return pl.get("noti_region") or pl.get("lock_region") or ""
    except Exception:
        return ""


def decode_jwt_payload(jwt: str) -> dict:
    try:
        p = jwt.split(".")[1]
        p += "=" * ((4 - len(p) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(p).decode())
    except Exception:
        return {}


# ============================================================
# FLASK APP
# ============================================================
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# CORS
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "JWT Generator",
        "version": "1.0",
        "endpoints": {
            "GET  /health":               "health check",
            "GET  /api/jwt":              "uid + password as query params",
            "POST /api/jwt":              "body: {uid, password}",
            "POST /api/jwt/from-token":   "body: {access_token, open_id}",
        },
        "example": {
            "POST /api/jwt": {"uid": "7918948306", "password": "OBSCURACODER_48291"},
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
    else:
        body     = request.get_json(silent=True) or {}
        uid      = body.get("uid")
        password = body.get("password")

    if not uid or not password:
        return jsonify({"error": "uid and password required"}), 400

    try:
        access_token, open_id = get_access_token(str(uid), str(password))
        result = major_login(open_id, access_token)
        payload = decode_jwt_payload(result["token"])
        return jsonify({
            "success":      True,
            "access_token": access_token,
            "open_id":      open_id,
            "jwt":          result["token"],
            "region":       payload.get("noti_region") or result.get("lockRegion"),
            "account_id":   payload.get("account_id"),
            "nickname":     payload.get("nickname"),
            "is_emulator":  payload.get("is_emulator"),
            "expires_at":   payload.get("exp"),
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

    if not access_token or not open_id:
        return jsonify({"error": "access_token and open_id required"}), 400

    try:
        result = major_login(str(open_id), str(access_token))
        payload = decode_jwt_payload(result["token"])
        return jsonify({
            "success":      True,
            "access_token": access_token,
            "open_id":      open_id,
            "jwt":          result["token"],
            "region":       payload.get("noti_region") or result.get("lockRegion"),
            "account_id":   payload.get("account_id"),
            "nickname":     payload.get("nickname"),
            "is_emulator":  payload.get("is_emulator"),
            "expires_at":   payload.get("exp"),
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
def server_error(e):
    return jsonify({"error": "internal server error"}), 500


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = 8000
    print(f"[*] JWT Generator API starting on http://{HOST}:{PORT}")
    print(f"[*] Endpoints:")
    print(f"      GET  /api/jwt?uid=...&password=...")
    print(f"      POST /api/jwt            {{uid, password}}")
    print(f"      POST /api/jwt/from-token {{access_token, open_id}}")
    print()
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
