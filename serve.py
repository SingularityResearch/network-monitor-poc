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

DEFAULT_PORT = 8080

# Global network collector instance
collector = RealNetworkCollector()

class NetworkMonitorHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Handles both static dashboard files and live network telemetry API requests."""

    def end_headers(self):
        if self.path.startswith('/api/'):
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == '/api/network-telemetry':
            params = urllib.parse.parse_qs(parsed.query)
            scope = params.get('scope', ['all'])[0]
            k_val = params.get('k', ['4'])[0]
            target_k = int(k_val) if k_val.isdigit() else 4

            data = collector.get_topology(scope=scope, target_k=target_k)
            payload = json.dumps(data).encode('utf-8')

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        elif parsed.path == '/api/trigger-scan':
            threading.Thread(target=collector.scan_lan_subnet, daemon=True).start()
            payload = json.dumps({'status': 'scanning', 'message': 'LAN subnet ping sweep started'}).encode('utf-8')

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # Serve static dashboard files
        super().do_GET()


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def kill_process_on_port(port: int):
    """Detect and terminate any existing process holding the given port."""
    my_pid = os.getpid()
    pids = set()

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


def open_browser(url: str):
    """Open default web browser after server has started."""
    time.sleep(0.4)
    print(f"[serve.py] Opening default web browser to: {url}")
    try:
        if not webbrowser.open(url):
            subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        try:
            subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            print(f"[serve.py] Could not open browser automatically: {e}")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else DEFAULT_PORT
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    if is_port_in_use(port):
        kill_process_on_port(port)

    url = f"http://localhost:{port}/index.html"

    threading.Thread(target=open_browser, args=(url,), daemon=True).start()

    socketserver.TCPServer.allow_reuse_address = True

    try:
        with socketserver.TCPServer(("", port), NetworkMonitorHTTPHandler) as httpd:
            print(f"[serve.py] Serving Network Monitor with Live Telemetry API on http://0.0.0.0:{port} ...")
            print(f"[serve.py] Telemetry API: http://localhost:{port}/api/network-telemetry")
            print("Press Ctrl+C to stop the server.")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[serve.py] Shutting down server.")
    except Exception as e:
        print(f"[serve.py] Error starting server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
