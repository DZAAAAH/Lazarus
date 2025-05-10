#!/usr/bin/env python3
"""
LAZARUS v9.7 EXTREME - All-in-One CTF & Pentest Toolkit (Auto Flag Hunter)
"""

import argparse, re, base64, binascii, requests, itertools, time, os, socket
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, quote_plus

try:
    from pyfiglet import Figlet
    from colorama import Fore, init as color_init
    color_init(autoreset=True)
    USE_FIGLET = True
except ImportError:
    USE_FIGLET = False

def show_banner():
    if USE_FIGLET:
        f = Figlet(font='slant')
        print(Fore.CYAN + f.renderText('LAZARUS'))
    print(Fore.GREEN + "Auto-Flag Hunter Supreme v9.7 EXTREME MODE")

def save_flag(flag):
    with open("flag_output.txt", "a") as f:
        f.write(flag + "\n")
    print(Fore.YELLOW + "[+] Flag saved to flag_output.txt")

def module_crypto(path):
    print("[*] Crypto: scanning encodings...")
    try:
        data = open(path, 'rb').read().decode('latin-1', errors='ignore')
        hexes = re.findall(r'\b[0-9A-Fa-f]{32,}\b', data)
        b64s = re.findall(r'(?:[A-Za-z0-9+/]{20,}={0,2})', data)
        b58s = re.findall(r'[1-9A-HJ-NP-Za-km-z]{20,}', data)
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
    except Exception as e:
        print("[-] Error:", e)

def module_web(url):
    print("[*] Web auto-exploit:", url)
    try:
        r = requests.get(url, timeout=6)
        html = r.text
        flags = re.findall(r'\w+\{.*?\}', html)
        if flags:
            for f in flags:
                print(Fore.CYAN + "[FLAG]", f)
                save_flag(f)
        else:
            print("[!] No direct flag found. Proceeding with advanced modules...")
    except Exception as e:
        print("[-] Web error:", e)

def module_spoof_request(url):
    print("[*] Fuzzing Headers for Bypass...")
    headers_list = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"Referer": "https://admin.ctf.local"},
        {"User-Agent": "Agent hackme"},
        {"Authorization": "Bearer root"},
        {"Host": "localhost"},
    ]
    for h in headers_list:
        try:
            r = requests.get(url, headers=h, timeout=5)
            flags = re.findall(r'\w+\{.*?\}', r.text)
            if flags:
                print(Fore.GREEN + f"[+] Flag found with headers {h}")
                for f in flags:
                    print(Fore.CYAN + "[FLAG]", f)
                    save_flag(f)
                return
        except: continue
    print("[-] Header spoofing gagal. [MANUAL REVIEW NEEDED]")

def module_auto_secret_hunter(url):
    print("[*] Bruteforce ?secret= menggunakan Bing Search...")
    try:
        parts = urlparse(url).path.strip('/').split('/')
        base_keywords = list(set(parts + [w for p in parts for w in re.split(r'[-_]', p)]))
        search_terms = '+'.join(base_keywords[:3])
        search_url = f"https://www.bing.com/search?q={quote_plus(search_terms + ' ctf secret')}"
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(search_url, headers=headers, timeout=8)
        hits = re.findall(r'<a href="[^"]+">([^<]+)</a>', r.text)
        candidates = set()
        for h in hits:
            clean = BeautifulSoup(h, 'html.parser').text
            found = re.findall(r'\b[a-zA-Z0-9]{5,25}\b', clean)
            for f in found:
                if f.lower() not in ['submit', 'index', 'ctf', 'home']:
                    candidates.add(f.lower())
        test_list = list(set(base_keywords + list(candidates)))[:25]
        print(f"[*] Mencoba {len(test_list)} kandidat sebagai ?secret=")
        for word in test_list:
            try:
                resp = requests.get(f"{url}?secret={quote_plus(word)}", timeout=4)
                flags = re.findall(r'\w+\{.*?\}', resp.text)
                if flags:
                    for f in flags:
                        print(Fore.CYAN + "[FLAG]", f)
                        save_flag(f)
                    return
            except: continue
        print("[-] Flag tidak ditemukan dari Bing. [MANUAL REVIEW NEEDED]")
    except:
        print("[-] Auto-Secret gagal. [MANUAL CHECK RECOMMENDED]")

def module_usb(path):
    print("[*] USB Forensic...")
    try:
        data = open(path, 'rb').read().decode('latin-1', errors='ignore')
        devs = re.findall(r'Disk&Ven_([\w\-]+)&Prod_([\w\-]+)', data)
        for v, p in devs:
            print(" Vendor:", v, "| Product:", p)
    except:
        print("[-] USB scan error.")

def module_win_forensic(path):
    print("[*] Windows Forensic: scanning registry artifacts...")
    try:
        data = open(path, 'rb').read()
        strings = re.findall(rb'[ -~]{6,}', data)
        for s in strings:
            decoded = s.decode('latin-1', errors='ignore')
            if re.search(r'pass|login|cred|flag|user', decoded, re.IGNORECASE):
                print("[+] Suspicious:", decoded)
    except:
        print("[-] Windows forensic failed.")

def module_log(path):
    print("[*] Log Analysis...")
    try:
        with open(path, 'r', errors='ignore') as f:
            for i, line in enumerate(f):
                if re.search(r'error|fail|unauth|malware|suspicious', line, re.IGNORECASE):
                    print(f"[!] Line {i}:", line.strip())
    except:
        print("[-] Log failed.")

def module_browser(path):
    print("[*] Browser Artifact Scan...")
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                if 'http' in line or 'search' in line:
                    print(" ", line.strip())
    except:
        print("[-] Browser read error.")

def module_evtx(path):
    print("[*] EVTX Log Scan...")
    try:
        import Evtx.Evtx as evtx
        from xml.etree import ElementTree as ET
        flags = []
        with evtx.Evtx(path) as log:
            for record in log.records():
                xml = ET.fromstring(record.xml())
                raw = ET.tostring(xml, encoding='unicode')
                flags += re.findall(r'\w+\{.*?\}', raw)
        for f in set(flags):
            print("[FLAG]", f)
            save_flag(f)
    except:
        print("[-] EVTX parsing failed.")

def module_pcap(path):
    print("[*] Wireshark/PCAP Scan (experimental)...")
    try:
        with open(path, 'rb') as f:
            raw = f.read().decode('latin-1', errors='ignore')
            flags = re.findall(r'\w+\{.*?\}', raw)
            if flags:
                for f in flags:
                    print("[FLAG]", f)
                    save_flag(f)
            else:
                print("[-] No flag in pcap. [MANUAL REVIEW RECOMMENDED]")
    except:
        print("[-] Failed reading .pcap")

def auto_module_router(target):
    if target.startswith("http"):
        module_web(target)
        module_spoof_request(target)
        module_auto_secret_hunter(target)
    elif os.path.isfile(target):
        name = os.path.basename(target).lower()
        ext = os.path.splitext(target)[1].lower()
        if ext == ".pcap": module_pcap(target)
        elif ext == ".evtx": module_evtx(target)
        elif ext in ['.log']: module_log(target)
        elif ext in ['.txt']: module_crypto(target)
        elif 'usb' in name: module_usb(target)
        elif 'ntuser' in name or 'system' in name: module_win_forensic(target)
        elif 'history' in name or 'browser' in name: module_browser(target)
        else:
            print("[!] Fallback mode aktif.")
            module_crypto(target)
    else:
        print("[-] Target tidak dikenali.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', required=True, help='Target file atau URL')
    args = parser.parse_args()
    show_banner()
    auto_module_router(args.target)

if __name__ == '__main__':
    main()
