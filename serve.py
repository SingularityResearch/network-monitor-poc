#!/usr/bin/env python3
"""
Local HTTP Server for K-Means Network Topology Monitor.
- Automatically kills any previous process occupying the port before binding.
- Automatically opens the system's default web browser to the index page.
"""
import sys
import os
import signal
import time
import subprocess
import threading
import http.server
import socketserver
import socket
import webbrowser

DEFAULT_PORT = 8080

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

    # Final fallback if port still appears occupied
    if is_port_in_use(port):
        try:
            subprocess.run(["fuser", "-k", "-9", f"{port}/tcp"], stderr=subprocess.DEVNULL)
            time.sleep(0.3)
        except Exception:
            pass

def open_browser(url: str):
    """Open the default system browser after the server has bound."""
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

    # Terminate any running process on this port so debugger starts cleanly
    if is_port_in_use(port):
        kill_process_on_port(port)

    url = f"http://localhost:{port}/index.html"

    # Start browser opener in background thread
    threading.Thread(target=open_browser, args=(url,), daemon=True).start()

    handler = http.server.SimpleHTTPRequestHandler
    socketserver.TCPServer.allow_reuse_address = True

    try:
        with socketserver.TCPServer(("", port), handler) as httpd:
            print(f"Serving HTTP on 0.0.0.0 port {port} ({url}) ...")
            print("Press Ctrl+C to stop the server.")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[serve.py] Shutting down server.")
    except Exception as e:
        print(f"[serve.py] Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
