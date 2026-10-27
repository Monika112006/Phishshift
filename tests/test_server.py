"""
Integration test for the PhishShift Web Server and REST API.
"""

import json
import threading
import time
import urllib.request
import urllib.parse
from app.server import PhishShiftHandler
import http.server


def run_integration_test():
    server_address = ("127.0.0.1", 8089)
    httpd = http.server.HTTPServer(server_address, PhishShiftHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    base_url = "http://127.0.0.1:8089"

    # Test 1: GET / (UI HTML)
    req1 = urllib.request.urlopen(f"{base_url}/")
    assert req1.status == 200
    html = req1.read().decode("utf-8")
    assert "PhishShift" in html
    assert "Live Triage Scanner" in html
    print("[PASS] GET / serves index.html with 200 OK")

    # Test 2: GET /api/benchmark
    req2 = urllib.request.urlopen(f"{base_url}/api/benchmark")
    assert req2.status == 200
    bench = json.loads(req2.read().decode("utf-8"))
    assert "models" in bench
    print("[PASS] GET /api/benchmark serves model benchmarks with 200 OK")

    # Test 3: POST /api/scan
    payload = json.dumps({
        "subject": "Urgent security update",
        "body": "Your mailbox password will expire in 2 hours. Update at hxxp://portal[.]xyz",
        "sender_domain_type": "free_webmail",
        "channel": "email",
        "inert_url": "hxxp://portal[.]xyz"
    }).encode("utf-8")

    req3 = urllib.request.Request(
        f"{base_url}/api/scan",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    resp3 = urllib.request.urlopen(req3)
    assert resp3.status == 200
    scan_res = json.loads(resp3.read().decode("utf-8"))
    assert "composite_risk_score" in scan_res
    assert "verdict" in scan_res
    print(f"[PASS] POST /api/scan returned verdict: {scan_res['verdict']} (Score: {scan_res['composite_risk_score']})")

    httpd.shutdown()
    print("[ALL HTTP SERVER TESTS PASSED SUCCESSFULLY!]")


if __name__ == "__main__":
    run_integration_test()
