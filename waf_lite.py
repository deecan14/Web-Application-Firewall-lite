import re
import logging
from flask import Flask, request, jsonify
import requests


app = Flask(__name__)


logging.basicConfig(
    filename="waf_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s- %(message)s"
)


WAF_RULES = {
    "SQL Injection": re.compile(r"(\bor\b|\band\b|\bunion\b|\bselect\b|\bdrop\b)", re.IGNORECASE),
    "XSS Attack": re.compile(r"(<script>|</script>|javascript:)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE)
}

TARGET_URL = "https://httpbin.org/get"


def check_request(data: str):
    """Check request against WAF rules."""
    for attack, pattern in WAF_RULES.items():
        if pattern.search(data):
            return attack
        return None


@app.route("/", methods=["GET","POST"])
def waf_proxy():
    query_string = request.query_string.decode("Utf-8")
    body_data = request.get_data(as_text=True)
    scan_data = query_string + " " + body_data

    result = check_request(scan_data)
    if result:
        log_msg = f"Block [{result}] - From {request.remote_addr} - Data: {scan_data}"
        logging.warning(log_msg)
        return jsonify({"Blocked": True, "reason": result}), 403

    if request.method == "GET":
        resp = requests.get(TARGET_URL, params=request.args)
    else:
        resp = requests.post(TARGET_URL, data=request.form)

    log_msg = f"ALLOWED -  From {request.remote_addr} - Data: {scan_data}"
    logging.warning(log_msg)

    return jsonify({
        "blocked": False,
        "forwarded_to": TARGET_URL,
        "response": resp.json()
    })


if __name__ == "__main__":
    print("WAF Lite running on http://127.0.0.1:5000")
    app.run(debug=True)
