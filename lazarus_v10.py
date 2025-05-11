#!/usr/bin/env python3
"""
LAZARUS v10 PRO+ - Ultimate CTF Toolkit (Auto Flag Hunter + Forensic + Web Exploit)
"""

import argparse, re, base64, binascii, requests, os, time, itertools, subprocess
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
    print(Fore.GREEN + "CTF Toolkit v10 PRO+ | Auto-Flag Hunter | Aggressive Mode")

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
        flags = re.findall(r'\w+\{.*?\}', r.text)
        for f in flags:
            print(Fore.CYAN + "[FLAG]", f)
            save_flag(f)
    except Exception as e:
        print("[-] Web error:", e)

def module_spoof_headers(url):
    print("[*] Header Spoof + Agent Hacker Mode...")
    headers_list = [
        {"User-Agent": "CTF-Hacker"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"Referer": "http://admin.local"},
        {"Authorization": "Bearer admin"}
    ]
    for h in headers_list:
        try:
            r = requests.get(url, headers=h, timeout=5)
            flags = re.findall(r'\w+\{.*?\}', r.text)
            if flags:
                for f in flags:
                    print(Fore.CYAN + "[FLAG]", f)
                    save_flag(f)
                return
        except: continue

def module_auto_secret_bing(url):
    print("[*] Bruteforce Secret via Bing...")
    try:
        q = '+'.join(urlparse(url).path.strip('/').split('/')) + "+ctf+secret"
        bing = f"https://www.bing.com/search?q={q}"
        r = requests.get(bing, timeout=5)
        hits = re.findall(r'<a.*?>(.*?)</a>', r.text)
        test_words = set()
        for h in hits:
            h = BeautifulSoup(h, 'html.parser').text
            words = re.findall(r'\b[a-zA-Z0-9]{5,25}\b', h)
            for w in words:
                test_words.add(w.lower())
        for w in list(test_words)[:20]:
            try:
                res = requests.get(f"{url}?secret={quote_plus(w)}", timeout=4)
                flags = re.findall(r'\w+\{.*?\}', res.text)
                if flags:
                    for f in flags:
                        print(Fore.CYAN + "[FLAG]", f)
                        save_flag(f)
                    return
            except: continue
        print("[-] Tidak ditemukan flag dari kandidat Bing.")
    except Exception as e:
        print("[-] Bing Secret error:", e)

def module_js_crawler(url):
    print("[*] Crawling JS files...")
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        for s in soup.find_all('script'):
            src = s.get('src')
            if src:
                full = urljoin(url, src)
                try:
                    js = requests.get(full, timeout=4).text
                    if 'flag' in js or 'secret' in js:
                        print(Fore.YELLOW + "[+] JS:", full)
                        print(js[:200])
                except: pass
    except:
        print("[-] JS crawl failed.")

def module_click_sim(url):
    print("[*] Simulasi klik otomatis (auto-event)...")
    try:
        r = requests.get(url, timeout=5)
        if 'onclick' in r.text or 'addEventListener' in r.text:
            print("[+] Ada event klik yang terdeteksi. Coba manual via browser + devtools.")
        else:
            print("[-] Tidak ada interaksi klik terdeteksi.")
    except:
        print("[-] Gagal fetch halaman.")

def module_dir_brute(url):
    print("[*] Brute force directory...")
    common = ['admin', 'flag', 'secret', 'config', '.git', '.env']
    for c in common:
        try:
            test = urljoin(url, c)
            r = requests.get(test, timeout=4)
            if r.status_code in [200, 403]:
                print("[+] Ditemukan:", test)
        except: continue

def module_log(path):
    print("[*] Log Analyzer:")
    with open(path, 'r', errors='ignore') as f:
        for i, line in enumerate(f):
            if re.search(r'error|fail|unauth|malware|flag', line, re.IGNORECASE):
                print(f"[!] [{i}]", line.strip())

def module_browser(path):
    print("[*] Browser Forensic: extracting terms...")
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            if 'http' in line or 'search' in line:
                print(" ", line.strip())

def module_usb(path):
    print("[*] USB Forensic:")
    data = open(path, 'rb').read().decode('latin-1', errors='ignore')
    devs = re.findall(r'Disk&Ven_([\w\-]+)&Prod_([\w\-]+)', data)
    for v, p in devs:
        print(" Vendor:", v, "Product:", p)

def module_win_forensic(path):
    print("[*] Windows Forensic:")
    data = open(path, 'rb').read()
    strings = re.findall(rb'[ -~]{6,}', data)
    for s in strings:
        d = s.decode('latin-1', errors='ignore')
        if re.search(r'flag|pass|cred|user|admin', d, re.IGNORECASE):
            print("[+] Found:", d)

def module_pcap_deep(path):
    print("[*] Deep PCAP Inspection (HTTP/Credentials/Cookies)...")
    try:
        import pyshark
        cap = pyshark.FileCapture(path, display_filter="http")
        for pkt in cap:
            try:
                if hasattr(pkt.http, 'file_data'):
                    body = pkt.http.file_data
                    flags = re.findall(r'\w+\{.*?\}', body)
                    for f in flags:
                        print("[FLAG]", f)
                        save_flag(f)
                elif hasattr(pkt.http, 'cookie'):
                    print("[+] Cookie found:", pkt.http.cookie)
                elif hasattr(pkt.http, 'authorization'):
                    print("[+] Authorization:", pkt.http.authorization)
            except: continue
        cap.close()
    except ImportError:
        print("[-] pyshark belum terinstall. Jalankan: pip install pyshark")
    except Exception as e:
        print("[-] PCAP deep analysis failed:", e)
        
def auto_router(target):
    if target.startswith("http"):
        module_web(target)
        module_spoof_headers(target)
        module_js_crawler(target)
        module_dir_brute(target)
        module_click_sim(target)
        module_auto_secret_bing(target)
    elif os.path.isfile(target):
        name = os.path.basename(target).lower()
        ext = os.path.splitext(target)[1].lower()
        if 'pcap' in ext: module_pcap_deep(target)
        elif 'log' in ext: module_log(target)
        elif 'usb' in name: module_usb(target)
        elif 'browser' in name or 'history' in name: module_browser(target)
        elif 'ntuser' in name or 'sam' in name: module_win_forensic(target)
        else: module_crypto(target)
    else:
        print("[-] Target tidak dikenali.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', required=True)
    args = parser.parse_args()
    show_banner()
    auto_router(args.target)

if __name__ == '__main__':
    main()



# ====== MODULE TAMBAHAN LANJUTAN ======

def module_flag_multi(text):
    patterns = [r'IDN_CTF\{.*?\}', r'FLAG\{.*?\}', r'[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}', r'eyJ[A-Za-z0-9-_]+\.']
    for pat in patterns:
        found = re.findall(pat, text)
        for f in found:
            print(Fore.MAGENTA + "[FIND]", f)
            save_flag(f)

def module_param_finder(url):
    print("[*] Parameter Finder:")
    try:
        r = requests.get(url, timeout=5)
        forms = BeautifulSoup(r.text, 'html.parser').find_all('form')
        for i, form in enumerate(forms):
            inputs = form.find_all('input')
            print(f"Form #{i+1} with action: {form.get('action')}")
            for inp in inputs:
                print("   Input:", inp.get('name'))
    except: print("[-] Param finder error.")

def module_form_bruter(url):
    print("[*] Form Bruter (default creds: admin/admin):")
    try:
        creds = [('admin', 'admin'), ('root', 'toor'), ('ctf', 'ctf123')]
        for u, p in creds:
            r = requests.post(url, data={'username': u, 'password': p}, timeout=5)
            if 'flag' in r.text.lower() or 'success' in r.text.lower():
                print(f"[+] Login sukses: {u}:{p}")
                flags = re.findall(r'\w+\{.*?\}', r.text)
                for f in flags:
                    print(Fore.CYAN + "[FLAG]", f)
                    save_flag(f)
                return
    except: print("[-] Form brute failed.")

def module_dom_xss_eval(url):
    print("[*] DOM XSS & eval() Checker:")
    try:
        r = requests.get(url, timeout=5)
        if any(x in r.text for x in ['eval(', 'document.write(', 'innerHTML']):
            print(Fore.RED + "[!] Potensi eval() atau DOM sink ditemukan!")
        else:
            print("[-] Tidak ada indikasi eval atau DOM sink.")
    except: print("[-] Gagal fetch halaman.")

def module_agent_rotation(url):
    print("[*] Aggressive Agent Spoofing:")
    uagents = [
        "Mozilla/5.0 (X11; Linux x86_64)",
        "curl/7.64.1", "Googlebot/2.1", "CTF-Scanner/1.0"
    ]
    for ua in uagents:
        try:
            r = requests.get(url, headers={'User-Agent': ua}, timeout=4)
            flags = re.findall(r'\w+\{.*?\}', r.text)
            for f in flags:
                print(Fore.CYAN + "[FLAG]", f)
                save_flag(f)
        except: continue

def module_js_deep_secrets(url):
    print("[*] Deep JS Secret Hunter:")
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        for s in soup.find_all('script'):
            src = s.get('src')
            if src:
                full = urljoin(url, src)
                try:
                    js = requests.get(full, timeout=4).text
                    secrets = re.findall(r'(token|key|flag)\s*[:=]\s*[\"\'](.*?)[\"\']', js, re.IGNORECASE)
                    for k, v in secrets:
                        print(f"[+] JS Secret {k}: {v}")
                        module_flag_multi(v)
                except: continue
    except: print("[-] Deep JS failed.")

def module_recursive_zip(path):
    print("[*] Recursive ZIP Extractor:")
    def extract_recursive(zfile, base):
        with zipfile.ZipFile(zfile, 'r') as z:
            z.extractall(base)
            for name in z.namelist():
                if name.endswith('.zip'):
                    extract_recursive(os.path.join(base, name), base)
    extract_dir = path + "_unzipped"
    os.makedirs(extract_dir, exist_ok=True)
    extract_recursive(path, extract_dir)
    print("[+] Extraction complete to:", extract_dir)
