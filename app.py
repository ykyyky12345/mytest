import os
import base64
import hashlib
import struct
from Cryptodome.Cipher import AES
from flask import Flask, request

app = Flask(__name__)

# ======================== 这里改成你企微后台生成的值 ========================
TOKEN = "vLooTlpQEuFKcIXkFfzH"
ENCODING_AES_KEY = "FDDZpYjeyM5dmmbfLY7bv05jabAQNRc4CfGyWRiNgms"
# ==========================================================================

AES_KEY = base64.b64decode(ENCODING_AES_KEY + "=")
IV = AES_KEY[:16]

def _pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def decrypt_echostr(echostr_b64):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
    decrypted_bytes = cipher.decrypt(base64.b64decode(echostr_b64))
    decrypted_bytes = _pkcs7_unpad(decrypted_bytes)
    msg_len = struct.unpack(">I", decrypted_bytes[16:20])[0]
    return decrypted_bytes[20:20+msg_len].decode("utf‑8")

@app.route("/", methods=["GET"])
def wecom_verify():
    msg_signature = request.args.get("msg_signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    echostr = request.args.get("echostr", "")

    sort_list = sorted([TOKEN, timestamp, nonce, echostr])
    calc_sign = hashlib.sha1("".join(sort_list).encode("utf‑8")).hexdigest()
    if calc_sign != msg_signature:
        return "signature error", 403
    try:
        return decrypt_echostr(echostr)
    except Exception as e:
        return f"decrypt error:{str(e)}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
