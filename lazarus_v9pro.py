#!/usr/bin/env python3
"""
LAZARUS v9.0 - Unified CTF Professional Toolkit
"""
import argparse, re, base64, binascii, requests, itertools, time, sys, zipfile, os, subprocess, tempfile
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote_plus

# Optional dependencies for banner
try:
    from pyfiglet import Figlet
    from colorama import Fore, Style, init as color_init
    color_init(autoreset=True)
    USE_FIGLET = True
except ImportError:
    USE_FIGLET = False

# Spoof request (header fuzz)
def spoof_request(url):
    print("[*] Running header fuzz & spoofing...")
    headers_list = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"Referer": "https://admin.ctf.local"},
        {"Host": "localhost"},
        {"Authorization": "Bearer admin"},
        {"User-Agent": "Mozilla/5.0 (CTF Agent)"},
    ]
    for h in headers_list:
        try:
            r = requests.get(url, headers=h, timeout=5)
            if re.search(r'\w+\{.*?\}', r.text):
                print(f"[+] Flag found with headers {h}: {r.text.strip()[:200]}")
                return
        except:
            pass
    print("[-] No flag via header spoofing.")

# Alias agent mode to spoof_request
module_agent_mode = spoof_request

# Banner display
def show_banner():
    if USE_FIGLET:
        f = Figlet(font='slant')
        art = f.renderText('LAZARUS')
        for line in art.splitlines():
            print(Fore.CYAN + line)
        print(Fore.GREEN + 'Auto-Flag Hunter Supreme v9.0')
    else:
        print("""
=== LAZARUS CTF PROFESSIONAL TOOLKIT ===
Auto-Flag Hunter Supreme v9.0
""")
    time.sleep(0.2)

# Basic Modules

def module_crypto(path):
    print("[*] Crypto: scanning encodings...")
    data = open(path, 'rb').read().decode('latin-1', errors='ignore')
    hexes = re.findall(r'\b[0-9A-Fa-f]{32,}\b', data)
    b64s  = re.findall(r'(?:[A-Za-z0-9+/]{20,}={0,2})', data)
    b58s  = re.findall(r'[{]?[1-9A-HJ-NP-Za-km-z]{20,}[}]?', data)
    for h in set(hexes):
        try: print(f"[hex] {h} -> {binascii.unhexlify(h).decode()}")
        except: pass
    for b in set(b64s):
        try: print(f"[b64] {b} -> {base64.b64decode(b).decode()}")
        except: pass
    for b in set(b58s):
        try:
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            num = 0
            for c in b.strip('{}'):
                num = num * 58 + alphabet.index(c)
            raw = num.to_bytes((num.bit_length()+7)//8, 'big')
            print(f"[b58] {b} -> {raw.decode('latin-1', errors='ignore')}")
        except: pass


def module_log(path):
    print("[*] Log Analysis:")
    with open(path, 'r', errors='ignore') as f:
        for i, line in enumerate(f):
            if re.search(r'error|fail|unauthorized|malware', line, re.IGNORECASE):
                print(f"[{i}] {line.strip()}")


def module_browser(path):
    print("[*] Browser Forensic: Extracting URLs...")
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            if 'http' in line:
                print("  ", line.strip())


def module_usb(path):
    print("[*] USB Forensic: Detecting USB devices...")
    data = open(path, 'rb').read().decode('latin-1', errors='ignore')
    devices = re.findall(r'Disk&Ven_([\w\-]+)&Prod_([\w\-]+)', data)
    for v, p in devices:
        print(f" Vendor: {v}, Product: {p}")


def module_evtx(path):
    try:
        import Evtx.Evtx as evtx
        from xml.etree import ElementTree as ET
    except ImportError:
        print("[Hint] Install python-evtx for EVTX parsing.")
        return
    print("[*] EVTX Parser: extracting flag fragments...")
    parts = []
    with evtx.Evtx(path) as log:
        for rec in log.records():
            try:
                xml = ET.fromstring(rec.xml())
                raw = ET.tostring(xml, encoding='unicode')
                parts += re.findall(r'\w+\{.*?\}', raw)
            except:
                pass
    for p in sorted(set(parts)):
        print(" ", p)


def module_web(url):
    print(f"[*] Web auto-exploit: {url}")
    try:
        r = requests.get(url, timeout=5)
        html = r.text
        scripts = re.findall(r'<script.*?>(.*?)</script>', html, re.DOTALL)
        comb = html + '\n'.join(scripts)
        for m in re.findall(r'\w+\{.*?\}', comb):
            print("[FLAG]", m)
    except Exception as e:
        print("[Error web]", e)


def module_ssti(url):
    print(f"[*] SSTI auto-scan: {url}")
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        form = soup.find('form')
        if not form:
            print("[-] No form for SSTI test.")
            return
        for inp in form.find_all('input'):
            name = inp.get('name')
            if not name: continue
            test = requests.post(url, data={name: '{{7*7}}'}, timeout=5)
            if '49' in test.text:
                print("[+] SSTI Detected!")
                return
    except Exception as e:
        print("[Error ssti]", e)

# Placeholder for advanced modules
# def module_secret_brute_google(url): ...
# def module_user_agent_spoof(url): ...
# def module_js_crawler(url): ...
# def module_click_simulator(url): ...

# Windows forensic modules
def module_win_forensic(path):
    print("[*] Windows Forensic: parsing image...")
    data = open(path, 'rb').read()
    strings = re.findall(rb'[ -~]{5,}', data)
    decoded = [s.decode('latin-1', errors='ignore') for s in strings]
    suspect = [s for s in decoded if re.search(r'pass|cred|user|login', s, re.IGNORECASE) and '.txt' in s]
    for s in suspect:
        print("[+] Suspect file:", s)


def module_ntfs_filewalker(path):
    print("[*] NTFS Explorer: listing virtual files...")
    raw = open(path,'rb').read().decode('latin-1', errors='ignore')
    files = re.findall(r'[A-Z]:\\[\\\w]+\\[\\\w]+\.txt', raw)
    for f in set(files):
        print(" [+]", f)

# Router and main logic
def auto_module_router(target):
    ext = os.path.splitext(target)[-1].lower()
    if ext in ['.ad1', '.dat', '.bin']:
        module_win_forensic(target)
        module_ntfs_filewalker(target)
        return
    if ext in ['.html', '.php', '.htm']:
        module_web(target)
        module_agent_mode(target)
        return
    # fallback to generic file modules
    if os.path.isfile(target):
        module_crypto(target)
        module_log(target)
        module_browser(target)
        module_usb(target)
    else:
        print("[Hint] Target not recognized.")


def main():
    parser = argparse.ArgumentParser(description='LAZARUS v9.0 - Unified CTF Toolkit')
    parser.add_argument('-t', '--target', required=True, help='URL or file path')
    args = parser.parse_args()
    show_banner()
    auto_module_router(args.target)

if __name__ == '__main__':
    main()
