"""
Zero-Dependency Web Application Server for PhishShift.
Provides REST API endpoints and serves a minimal, responsive web UI.
Exports top-level `app`, `application`, and `handler` variables for
seamless deployment on Vercel, Render, Railway, Gunicorn, and local Python.
"""

import http.server
import json
import os
import sys
import urllib.parse

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.engine import PhishShiftEngine
from src.models.rule_based import RuleBasedClassifier
from src.models.tfidf_linear import TFIDFLinearClassifier
from src.models.ensemble_model import MultiModalEnsembleClassifier

# Initialize triage engine
print("Initializing PhishShift Engine...", flush=True)
rules_clf = RuleBasedClassifier()
try:
    tfidf_clf = TFIDFLinearClassifier().load("models/tfidf_linear.json")
    ens_clf = MultiModalEnsembleClassifier().load("models/ensemble_forest.json")
    print("Loaded trained model artifacts.", flush=True)
except Exception as e:
    print(f"Artifacts load warning: {e}. Running with unpickled models.", flush=True)
    tfidf_clf = TFIDFLinearClassifier()
    ens_clf = MultiModalEnsembleClassifier()

engine = PhishShiftEngine(rules_clf, tfidf_clf, ens_clf)
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


# ---------------------------------------------------------------------------
# 1. BaseHTTPRequestHandler for standalone server and Vercel handler
# ---------------------------------------------------------------------------
class PhishShiftHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self.serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html")
        elif path.startswith("/static/"):
            rel_path = path[len("/static/"):]
            file_path = os.path.join(STATIC_DIR, rel_path)
            content_type = "text/plain"
            if file_path.endswith(".css"):
                content_type = "text/css"
            elif file_path.endswith(".js"):
                content_type = "application/javascript"
            elif file_path.endswith(".html"):
                content_type = "text/html"
            self.serve_file(file_path, content_type)
        elif path == "/api/benchmark":
            self.serve_json_file("evidence/model_benchmark_results.json")
        elif path == "/api/acceptance-tests":
            self.serve_json_file("evidence/acceptance_tests_evidence.json")
        elif path == "/api/robustness":
            self.serve_json_file("evidence/fr05_robustness_drift_evidence.json")
        elif path == "/api/manifest":
            self.serve_json_file("data/corpus_manifest.json")
        elif path == "/api/dedup-audit":
            self.serve_json_file("evidence/cp2_deduplication_audit.json")
        else:
            self.send_error(404, "Endpoint not found")

    def do_POST(self):
        if self.path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception:
                self.send_json({"error": "Invalid JSON payload"}, status=400)
                return

            result = engine.analyze_message(
                subject=payload.get("subject", ""),
                body=payload.get("body", ""),
                sender_domain_type=payload.get("sender_domain_type", "internal_corporate"),
                channel=payload.get("channel", "email"),
                inert_url=payload.get("inert_url", "")
            )
            self.send_json(result)
        else:
            self.send_error(404, "Endpoint not found")

    def serve_file(self, full_path: str, content_type: str):
        if not os.path.exists(full_path):
            self.send_error(404, f"File not found: {os.path.basename(full_path)}")
            return
        with open(full_path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def serve_json_file(self, rel_path: str):
        if not os.path.exists(rel_path):
            self.send_json({"status": "pending", "message": f"Evidence file {rel_path} not found."}, status=404)
            return
        with open(rel_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.send_json(data)

    def send_json(self, data, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# 2. Standard WSGI Application callable (for Vercel, Gunicorn, Render WSGI)
# ---------------------------------------------------------------------------
def wsgi_app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")

    headers = [
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
        ("Access-Control-Allow-Headers", "Content-Type"),
    ]

    if method == "OPTIONS":
        start_response("200 OK", headers)
        return [b""]

    if method == "GET":
        if path == "/" or path == "/index.html":
            file_path = os.path.join(STATIC_DIR, "index.html")
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    content = f.read()
                headers.extend([("Content-Type", "text/html"), ("Content-Length", str(len(content)))])
                start_response("200 OK", headers)
                return [content]

        elif path.startswith("/static/"):
            rel_path = path[len("/static/"):]
            file_path = os.path.join(STATIC_DIR, rel_path)
            if os.path.exists(file_path):
                content_type = "text/plain"
                if file_path.endswith(".css"):
                    content_type = "text/css"
                elif file_path.endswith(".js"):
                    content_type = "application/javascript"
                elif file_path.endswith(".html"):
                    content_type = "text/html"
                with open(file_path, "rb") as f:
                    content = f.read()
                headers.extend([("Content-Type", content_type), ("Content-Length", str(len(content)))])
                start_response("200 OK", headers)
                return [content]

        # Evidence / JSON API endpoints
        endpoint_map = {
            "/api/benchmark": "evidence/model_benchmark_results.json",
            "/api/acceptance-tests": "evidence/acceptance_tests_evidence.json",
            "/api/robustness": "evidence/fr05_robustness_drift_evidence.json",
            "/api/manifest": "data/corpus_manifest.json",
            "/api/dedup-audit": "evidence/cp2_deduplication_audit.json"
        }
        if path in endpoint_map:
            rel = endpoint_map[path]
            if os.path.exists(rel):
                with open(rel, "rb") as f:
                    content = f.read()
                headers.extend([("Content-Type", "application/json"), ("Content-Length", str(len(content)))])
                start_response("200 OK", headers)
                return [content]
            else:
                body = json.dumps({"status": "pending", "file": rel}).encode("utf-8")
                headers.extend([("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
                start_response("404 Not Found", headers)
                return [body]

    elif method == "POST" and path == "/api/scan":
        try:
            content_length = int(environ.get("CONTENT_LENGTH", 0))
        except (ValueError, TypeError):
            content_length = 0
        body_bytes = environ["wsgi.input"].read(content_length) if content_length > 0 else b"{}"
        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            payload = {}

        result = engine.analyze_message(
            subject=payload.get("subject", ""),
            body=payload.get("body", ""),
            sender_domain_type=payload.get("sender_domain_type", "internal_corporate"),
            channel=payload.get("channel", "email"),
            inert_url=payload.get("inert_url", "")
        )
        body = json.dumps(result, indent=2).encode("utf-8")
        headers.extend([("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        start_response("200 OK", headers)
        return [body]

    # Default 404
    start_response("404 Not Found", headers + [("Content-Type", "text/plain")])
    return [b"Endpoint not found"]


# ---------------------------------------------------------------------------
# 3. Top-Level Exports: Required by Vercel, Gunicorn, Render, and Serverless
# ---------------------------------------------------------------------------
app = wsgi_app
application = wsgi_app
handler = PhishShiftHandler


# ---------------------------------------------------------------------------
# 4. Standalone Server runner
# ---------------------------------------------------------------------------
def run_server(port: int = 8000):
    server_address = ("0.0.0.0", port)
    httpd = http.server.HTTPServer(server_address, PhishShiftHandler)
    print(f"============================================================", flush=True)
    print(f"  PhishShift Message Risk Scanner Web Server Started!", flush=True)
    print(f"  Access the UI at: http://localhost:{port}", flush=True)
    print(f"============================================================", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.", flush=True)
        httpd.server_close()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    run_server(port=port)
