#!/usr/bin/env python3
"""
Local HTTP Server for K-Means Network Topology Monitor.
- Serves static dashboard UI and assets.
- Provides REST API (/api/network-telemetry) for live Linux internal & public network telemetry.
- Automatically clears previous process on port before binding.
- Automatically opens system default browser.
"""
import sys
import os
import json
import signal
import time
import subprocess
import threading
import urllib.parse
import http.server
import socketserver
import socket
import webbrowser

from telemetry import RealNetworkCollector
from database import db
from threat_engine import threat_engine

DEFAULT_PORT = 8080

# Global network collector instance
collector = RealNetworkCollector()
last_db_record_time = 0.0

def background_history_recorder():
    """Continuously captures network telemetry snapshots into SQLite with rolling 48-hour retention."""
    global last_db_record_time
    while True:
        try:
            time.sleep(5.0)
            now = time.time()
            if now - last_db_record_time >= 4.5:
                topo = collector.get_topology(scope='all', target_k=4, resolve_dns=True, resolve_geoip=True)
                if topo and topo.get('nodes'):
                    db.record_snapshot(topo)
                    last_db_record_time = now
        except Exception:
            pass

# Start daemon thread to capture background network history
history_daemon = threading.Thread(target=background_history_recorder, daemon=True, name="SQLiteHistoryRecorder")
history_daemon.start()


class NetworkMonitorHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Handles both static dashboard files and live network telemetry API requests."""

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        if self.path.startswith('/api/'):
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def send_json_response(self, data, status_code=200):
        payload = json.dumps(data).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == '/favicon.ico':
            self.send_response(204)
            self.end_headers()
            return

        if parsed.path == '/api/network-telemetry':
            global last_db_record_time
            params = urllib.parse.parse_qs(parsed.query)
            scope = params.get('scope', ['all'])[0]
            k_val = params.get('k', ['4'])[0]
            target_k = int(k_val) if k_val.isdigit() else 4
            resolve_dns = params.get('resolve_dns', ['true'])[0].lower() in ('true', '1', 'yes')
            resolve_geoip = params.get('resolve_geoip', ['true'])[0].lower() in ('true', '1', 'yes')

            data = collector.get_topology(scope=scope, target_k=target_k, resolve_dns=resolve_dns, resolve_geoip=resolve_geoip)

            # Record snapshot to SQLite database (rate-limited to at most once per 3s)
            now = time.time()
            if now - last_db_record_time >= 3.0:
                try:
                    db.record_snapshot(data)
                    last_db_record_time = now
                except Exception as err:
                    print(f"[serve.py] Warning recording snapshot: {err}")

            self.send_json_response(data)
            return

        elif parsed.path == '/api/history/snapshots':
            params = urllib.parse.parse_qs(parsed.query)
            since_val = params.get('since', [None])[0]
            since = None
            if since_val is not None:
                try:
                    since = float(since_val)
                except ValueError:
                    since = None
            limit_val = params.get('limit', ['150'])[0]
            limit = int(limit_val) if limit_val.isdigit() else 150
            summary = params.get('summary', ['true'])[0].lower() in ('true', '1', 'yes')

            snapshots = db.get_snapshots(since=since, limit=limit, summary_only=summary)
            self.send_json_response({
                'status': 'ok',
                'snapshots': snapshots,
                'count': len(snapshots),
                'stats': db.get_stats()
            })
            return

        elif parsed.path == '/api/history/snapshot':
            params = urllib.parse.parse_qs(parsed.query)
            id_val = params.get('id', [None])[0]
            if id_val and id_val.isdigit():
                snap = db.get_snapshot_by_id(int(id_val))
                if snap:
                    self.send_json_response({'status': 'ok', 'snapshot': snap})
                else:
                    self.send_json_response({'status': 'error', 'message': f'Snapshot {id_val} not found'}, status_code=404)
            else:
                self.send_json_response({'status': 'error', 'message': 'Missing or invalid id parameter'}, status_code=400)
            return

        elif parsed.path == '/api/history/stats':
            self.send_json_response({
                'status': 'ok',
                'stats': db.get_stats()
            })
            return

        elif parsed.path == '/api/trigger-scan':
            threading.Thread(target=collector.scan_lan_subnet, daemon=True).start()
            self.send_json_response({'status': 'scanning', 'message': 'LAN subnet ping sweep started'})
            return

        elif parsed.path == '/api/relationships':
            data = collector.get_topology(scope='all', target_k=4, resolve_dns=True, resolve_geoip=True)
            self.send_json_response({
                'status': 'ok',
                'relationships': data.get('relationships', {}),
                'meta': data.get('meta', {})
            })
            return

        elif parsed.path == '/api/threats':
            params = urllib.parse.parse_qs(parsed.query)
            limit_val = params.get('limit', ['100'])[0]
            limit = int(limit_val) if limit_val.isdigit() else 100
            severity = params.get('severity', [None])[0]
            
            threats_summary = threat_engine.get_threats_summary() if threat_engine else {}
            db_threats = db.get_threats(limit=limit, severity=severity)
            
            self.send_json_response({
                'status': 'ok',
                'summary': threats_summary,
                'dbThreats': db_threats,
                'dbStats': db.get_threat_stats()
            })
            return

        # Static file mapping: serve directly with 200 OK and strict no-cache headers
        # to ensure the browser never receives a stale 304 Not Modified response.
        STATIC_FILE_MAP = {
            '/': ('index.html', 'text/html; charset=utf-8'),
            '/index.html': ('index.html', 'text/html; charset=utf-8'),
            '/styles.css': ('styles.css', 'text/css; charset=utf-8'),
            '/app.js': ('app.js', 'application/javascript; charset=utf-8'),
            '/chart.js': ('chart.js', 'application/javascript; charset=utf-8'),
            '/kmeans.js': ('kmeans.js', 'application/javascript; charset=utf-8'),
        }

        clean_path = parsed.path
        if clean_path in STATIC_FILE_MAP:
            filename, content_type = STATIC_FILE_MAP[clean_path]
            base_dir = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_dir, filename)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', content_type)
                    self.send_header('Content-Length', str(len(content)))
                    self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
                    self.send_header('Pragma', 'no-cache')
                    self.send_header('Expires', '0')
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception as e:
                    print(f"[serve.py] Error reading static file {filename}: {e}")

        # Fallback to standard handler for any other requests
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == '/api/threats/update':
            if threat_engine:
                threading.Thread(target=threat_engine.trigger_feed_update, daemon=True).start()
                self.send_json_response({
                    'status': 'updating',
                    'message': 'Threat signature and CVE feed update initiated',
                    'summary': threat_engine.get_threats_summary()
                })
            else:
                self.send_json_response({'status': 'error', 'message': 'Threat engine not available'}, status_code=500)
            return

        elif parsed.path == '/api/threats/clear':
            if threat_engine:
                with threat_engine.lock:
                    threat_engine.recent_threats.clear()
                    threat_engine.active_threat_map.clear()
            self.send_json_response({'status': 'cleared', 'message': 'Active threats buffer cleared'})
            return

        self.send_response(404)
        self.end_headers()



def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def kill_process_on_port(port: int):
    """Detect and terminate any existing process holding the given port."""
    my_pid = os.getpid()
    pids = set()

    # Try pgrep for existing serve.py processes
    try:
        out = subprocess.check_output(["pgrep", "-f", "serve.py"], stderr=subprocess.DEVNULL).decode().strip()
        for p in out.split():
            if p.isdigit() and int(p) != my_pid:
                pids.add(int(p))
    except Exception:
        pass

    # Try lsof
    try:
        out = subprocess.check_output(["lsof", "-ti", f":{port}"], stderr=subprocess.DEVNULL).decode().strip()
        for p in out.split():
            if p.isdigit() and int(p) != my_pid:
                pids.add(int(p))
    except Exception:
        pass

    # Try fuser if lsof didn't find anything
    if not pids:
        try:
            out = subprocess.check_output(["fuser", f"{port}/tcp"], stderr=subprocess.DEVNULL).decode().strip()
            for p in out.split():
                if p.isdigit() and int(p) != my_pid:
                    pids.add(int(p))
        except Exception:
            pass

    if pids:
        for pid in pids:
            try:
                print(f"[serve.py] Terminating existing process {pid} on port {port}...")
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass

        # Wait up to 2 seconds for port to clear
        for _ in range(20):
            time.sleep(0.1)
            if not is_port_in_use(port):
                break
        else:
            # Force kill if still occupied
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            time.sleep(0.2)

    if is_port_in_use(port):
        try:
            subprocess.run(["fuser", "-k", "-9", f"{port}/tcp"], stderr=subprocess.DEVNULL)
            time.sleep(0.3)
        except Exception:
            pass


def wait_for_server(port: int, max_retries: int = 50, delay: float = 0.05) -> bool:
    """Wait until the HTTP server is actively responding on the target port."""
    for _ in range(max_retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    return True
        except Exception:
            pass
        time.sleep(delay)
    return False


def open_browser(url: str, port: int):
    """Open default web browser directly to url after server has started and is listening."""
    if os.environ.get("NO_BROWSER", "").lower() in ("1", "true", "yes"):
        return
    if "--no-browser" in sys.argv:
        return

    # Ensure server is fully listening before launching browser
    if not wait_for_server(port, max_retries=60, delay=0.05):
        print(f"[serve.py] Warning: Server not responding yet on port {port}")
        return

    print(f"[serve.py] Opening web browser to: {url}")

    # Use xdg-open via desktop session so it opens in user's active browser
    try:
        if subprocess.call(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            return
    except Exception:
        pass

    # Fallback to python webbrowser module
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"[serve.py] Could not open browser automatically: {e}")


def main():
    port = DEFAULT_PORT
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)
            break

    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    if is_port_in_use(port):
        kill_process_on_port(port)

    url = f"http://localhost:{port}/index.html"

    # Browser opening is opt-in via --open or -o flag so that unwanted blank snap Chromium windows are never launched
    auto_open = ("--open" in sys.argv or "-o" in sys.argv)
    if auto_open:
        threading.Thread(target=open_browser, args=(url, port), daemon=True).start()
    else:
        print(f"[serve.py] Dashboard ready at: {url}")

    BaseServerClass = getattr(http.server, 'ThreadingHTTPServer', socketserver.ThreadingTCPServer)

    class ReusableThreadingServer(BaseServerClass):
        allow_reuse_address = True
        daemon_threads = True

        def server_bind(self):
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception:
                pass
            super().server_bind()

    # Retry bind if port is briefly in TIME_WAIT or clearing
    max_bind_attempts = 5
    httpd = None
    for attempt in range(max_bind_attempts):
        try:
            httpd = ReusableThreadingServer(("", port), NetworkMonitorHTTPHandler)
            break
        except OSError as e:
            if getattr(e, 'errno', None) == 98 and attempt < max_bind_attempts - 1:
                kill_process_on_port(port)
                time.sleep(0.5)
            else:
                print(f"\n[serve.py] Error starting server on port {port}: {e}")
                print(f"[serve.py] Port {port} is in use. Run:")
                print(f"    sudo fuser -k -9 {port}/tcp")
                print(f"or launch with an alternate port:")
                print(f"    python3 serve.py 8081\n")
                sys.exit(1)

    try:
        with httpd:
            print(f"[serve.py] Serving Network Monitor with Live Telemetry API on http://0.0.0.0:{port} ...")
            print(f"[serve.py] Open dashboard in browser: {url}")
            print(f"[serve.py] Telemetry API: http://localhost:{port}/api/network-telemetry")
            print("Press Ctrl+C to stop the server.")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[serve.py] Shutting down server.")
    except Exception as e:
        print(f"[serve.py] Server error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
