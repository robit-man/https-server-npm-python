#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import shutil
import threading
import itertools
import time
import socket
import ssl
import ipaddress
import urllib.request
from datetime import datetime, timedelta
from http.server import HTTPServer, SimpleHTTPRequestHandler

# ─── Constants ───────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH  = os.path.join(SCRIPT_DIR, "config.json")
VENV_FLAG    = "--in-venv"
VENV_DIR     = os.path.join(SCRIPT_DIR, "venv")
HTTPS_PORT   = 443

# ─── Spinner for long operations ──────────────────────────────────────────────
class Spinner:
    def __init__(self, msg):
        self.msg   = msg
        self.spin  = itertools.cycle("|/-\\")
        self._stop = threading.Event()
        self._thr  = threading.Thread(target=self._run, daemon=True)
    def _run(self):
        while not self._stop.is_set():
            sys.stdout.write(f"\r{self.msg} {next(self.spin)}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " "*(len(self.msg)+2) + "\r")
        sys.stdout.flush()
    def __enter__(self): self._thr.start()
    def __exit__(self, exc_type, exc, tb):
        self._stop.set(); self._thr.join()

# ─── Virtualenv bootstrap ─────────────────────────────────────────────────────
def bootstrap_and_run():
    # if we're not yet in-venv, create venv & install cryptography, then re-exec
    if VENV_FLAG not in sys.argv:
        if not os.path.isdir(VENV_DIR):
            with Spinner("Creating virtualenv…"):
                subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])
        pip = os.path.join(VENV_DIR, "Scripts" if os.name=="nt" else "bin", "pip")
        with Spinner("Installing dependencies…"):
            subprocess.check_call([pip, "install", "cryptography"])
        py = os.path.join(VENV_DIR, "Scripts" if os.name=="nt" else "bin", "python")
        os.execv(py, [py, __file__, VENV_FLAG] + sys.argv[1:])
    else:
        # now we're in-venv, drop the flag and proceed
        sys.argv.remove(VENV_FLAG)
        main()

# ─── Config I/O ───────────────────────────────────────────────────────────────
def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            return json.load(open(CONFIG_PATH))
        except:
            pass
    return {"serve_path": os.getcwd()}

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=4)

# ─── Auto-detect Node app dir ─────────────────────────────────────────────────
def find_node_app_dir(base):
    # check base first
    if os.path.exists(os.path.join(base, "server.js")) and os.path.exists(os.path.join(base, "package.json")):
        return base
    # else walk
    for root, dirs, files in os.walk(base):
        if "server.js" in files and "package.json" in files:
            return root
    return None

# ─── Networking Helpers ──────────────────────────────────────────────────────
def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]; s.close()
    return ip

def get_public_ip():
    try:
        return urllib.request.urlopen("https://api.ipify.org").read().decode().strip()
    except:
        return None

# ─── ASCII Banner ────────────────────────────────────────────────────────────
def print_banner(lan, public):
    lines = [f"  Local : https://{lan}", f"  Public: https://{public}" if public else "  Public: <none>"]
    w = max(len(l) for l in lines) + 4
    print("\n╔" + "═"*w + "╗")
    for l in lines:
        print("║" + l.ljust(w) + "║")
    print("╚" + "═"*w + "╝\n")

# ─── Certificate Generation ──────────────────────────────────────────────────
def generate_cert(cert_file, key_file):
    lan_ip    = get_lan_ip()
    public_ip = get_public_ip()

    # --- try mkcert install if missing ---
    if not shutil.which("mkcert"):
        if sys.platform.startswith("linux"):
            with Spinner("Installing mkcert…"):
                subprocess.check_call(["sudo","apt","update"])
                subprocess.check_call(["sudo","apt","install","-y","libnss3-tools","wget"])
                url = subprocess.check_output([
                    "bash","-lc",
                    "curl -s https://api.github.com/repos/FiloSottile/mkcert/releases/latest"
                    " | grep browser_download_url | grep linux-amd64 | cut -d '\"' -f4"
                ], shell=True, text=True).strip()
                subprocess.check_call(["wget","-O","mkcert",url])
                subprocess.check_call(["chmod","+x","mkcert"])
                subprocess.check_call(["sudo","mv","mkcert","/usr/local/bin/"])
        elif sys.platform=="darwin":
            with Spinner("Installing mkcert via Homebrew…"):
                subprocess.check_call(["brew","install","mkcert","nss"])
        elif os.name=="nt":
            with Spinner("Installing mkcert via Chocolatey…"):
                subprocess.check_call(["choco","install","mkcert","-y"])

    # --- generate with mkcert if available ---
    if shutil.which("mkcert"):
        cmd = ["mkcert","-install", lan_ip, "localhost", "127.0.0.1"]
        if public_ip:
            cmd.append(public_ip)
        with Spinner("Generating mkcert certificates…"):
            subprocess.run(cmd, check=True)
        import glob
        pems = sorted(glob.glob(f"{lan_ip}+*.pem"))
        keys = sorted(glob.glob(f"{lan_ip}+*-key.pem"))
        if pems and keys:
            shutil.copy(pems[-1], cert_file)
            shutil.copy(keys[-1], key_file)
            return

    # --- fallback to self-signed via cryptography ---
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509 import NameOID, SubjectAlternativeName, DNSName
    import cryptography.x509 as x509

    keyobj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san_list = [
        DNSName(lan_ip),
        DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
    ]
    if public_ip:
        san_list.append(x509.IPAddress(ipaddress.IPv4Address(public_ip)))
    san  = SubjectAlternativeName(san_list)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, lan_ip)])

    with Spinner("Generating self-signed certificate…"):
        cert = (
            x509.CertificateBuilder()
               .subject_name(name)
               .issuer_name(name)
               .public_key(keyobj.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(datetime.utcnow())
               .not_valid_after(datetime.utcnow()+timedelta(days=365))
               .add_extension(san, critical=False)
               .sign(keyobj, hashes.SHA256())
        )
    with open(key_file,"wb") as f:
        f.write(keyobj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    with open(cert_file,"wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

# ─── Main Flow ────────────────────────────────────────────────────────────────
def main():
    # 1) Load/write config
    cfg = load_config()

    # 2) Auto-detect Node app dir
    auto = find_node_app_dir(SCRIPT_DIR)
    if auto and cfg.get("serve_path") != auto:
        cfg["serve_path"] = auto
        save_config(cfg)
    elif not os.path.exists(CONFIG_PATH):
        # only prompt if we never had a config and auto-detect failed
        cfg["serve_path"] = input(f"Serve path [{cfg['serve_path']}]: ") or cfg["serve_path"]
        save_config(cfg)

    # 3) cd into it
    os.chdir(cfg["serve_path"])

    # 4) generate key.pem & cert.pem *before* any sudo-restart
    cert_file = os.path.join(cfg["serve_path"], "cert.pem")
    key_file  = os.path.join(cfg["serve_path"], "key.pem")
    generate_cert(cert_file, key_file)

    # 5) if not root yet, re-exec under sudo but keep venv
    if os.geteuid() != 0:
        print("⚠ Need root to bind port 443; re-running with sudo…")
        os.environ["SERVER_PY_ROOT"] = "1"
        # preserve the --in-venv flag
        args = [sys.executable, __file__, VENV_FLAG] + sys.argv[1:]
        os.execvp("sudo", ["sudo"] + args)

    # 6) build SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    # 7) show URLs
    print_banner(get_lan_ip(), get_public_ip())

    # 8) if Node.js app exists, npm install & npm run start
    if os.path.exists("package.json") and os.path.exists("server.js") and shutil.which("node"):
        # inject HTTPS shim
        patch = os.path.join(cfg["serve_path"], "tls_patch.js")
        with open(patch, "w") as f:
            f.write("""\
const fs = require('fs');
const https = require('https');
const http = require('http');
http.createServer = (opts, listener) => {
  if (typeof opts === 'function') listener = opts;
  return https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
  }, listener);
};""")
        env = os.environ.copy()
        env["PORT"] = str(HTTPS_PORT)
        with Spinner("Installing npm dependencies…"):
            subprocess.check_call(["npm","install"], cwd=cfg["serve_path"], env=env)
        # ensure patch loads
        existing = env.get("NODE_OPTIONS","")
        env["NODE_OPTIONS"] = f"{existing} -r {patch}".strip()
        with Spinner("Starting Node.js (HTTPS on 443)…"):
            proc = subprocess.Popen(["npm","run","start"], cwd=cfg["serve_path"], env=env)
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
    else:
        # pure-Python HTTPS fallback
        httpd = HTTPServer(("0.0.0.0", HTTPS_PORT), SimpleHTTPRequestHandler)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    bootstrap_and_run()
