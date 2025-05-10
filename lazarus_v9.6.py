#!/usr/bin/env python3
"""
LAZARUS v9.6 EXTENDED - CTF Toolkit with Auto-Flag Hunter + Auto-XSS + JS Analyzer
"""

import argparse, re, base64, binascii, requests, itertools, time, os
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
    print(Fore.GREEN + "Auto-Flag Hunter Supreme v9.6")

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
        r = requests.get(url, timeout=5)
        html = r.text
        flags = re.findall(r'\w+\{.*?\}', html)
        for f in flags:
            print(Fore.CYAN + "[FLAG]", f)
            save_flag(f)
    except Exception as e:
        print("[-] Web error:", e)

def module_spoof_request(url):
    print("[*] Fuzzing Headers for Bypass...")
    headers_list = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"Referer": "https://admin.ctf.local"},
        {"User-Agent": "Agent hackme"},
        {"Authorization": "Bearer root"}
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
        except:
            continue
    print("[-] Tidak ditemukan flag dari kombinasi header umum.")

def module_auto_secret_hunter(url):
    print("[*] Auto-Secret Hunter: scanning keyword from URL & Google...")
    try:
        parts = urlparse(url).path.strip('/').split('/')
        base_keywords = list(set(parts + [w for p in parts for w in re.split(r'[-_]', p)]))
        print(f"[+] Keywords from URL: {base_keywords[:6]}")
        search_terms = '+'.join(base_keywords[:3])
        search_url = f"https://html.duckduckgo.com/html/?q={search_terms}+ctf+secret"
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(search_url, headers=headers, timeout=8)
        hits = re.findall(r'<a.*?href=".*?">(.*?)</a>', r.text, re.DOTALL)
        candidates = set()
        for h in hits:
            clean = BeautifulSoup(h, 'html.parser').text
            found = re.findall(r'\b[a-zA-Z0-9]{5,25}\b', clean)
            for f in found:
                if f.lower() not in ['submit', 'ctf', 'index', 'home']:
                    candidates.add(f.lower())
        test_list = list(set(base_keywords + list(candidates)))[:25]
        print(f"[*] Mencoba {len(test_list)} kandidat sebagai ?secret=")
        for word in test_list:
            try:
                resp = requests.get(f"{url}?secret={quote_plus(word)}", timeout=5)
                flags = re.findall(r'\w+\{.*?\}', resp.text)
                if flags:
                    for f in flags:
                        print(Fore.CYAN + "[FLAG]", f)
                        save_flag(f)
                    return
            except:
                continue
        print("[-] Tidak ditemukan flag dari kandidat Google.")
    except Exception as e:
        print(f"[-] Auto-Secret error: {e}")

# (Modul XSS dan eksternal JS analyzer akan ditambahkan setelah konfirmasi lanjut)


def auto_module_router(target):
    if target.startswith("http"):
        module_web(target)
        module_spoof_request(target)
        module_auto_secret_hunter(target)
    else:
        print("[-] Target tidak dikenali.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', required=True, help='Target URL atau file')
    args = parser.parse_args()
    show_banner()
    auto_module_router(args.target)

if __name__ == '__main__':
    main()
        
