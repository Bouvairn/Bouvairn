"""
 ██╗███╗   ██╗███████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║████╗  ██║██╔════╝██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║██╔██╗ ██║█████╗  ██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

InfoHunter - Comprehensive Information Gathering Tool
Author: InfoHunter
"""
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import socket
import threading
import requests
import csv
import datetime
import whois
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from PIL import Image
from PIL.ExifTags import TAGS
import PyPDF2


# ==============================
# CORE ENGINE
# ==============================

class ReconEngine:

    # ----------------------------
    # DNS RESOLVE
    # ----------------------------
    def resolve(self, target):
        results = []

        try:
            ip = socket.gethostbyname(target)
            results.append(("IPv4", ip))
        except Exception as e:
            results.append(("Error", str(e)))

        try:
            info = socket.getaddrinfo(target, None)
            ipv6 = list({i[4][0] for i in info if ":" in i[4][0]})

            for i in ipv6:
                results.append(("IPv6", i))

        except:
            pass

        return results

    # ----------------------------
    # WHOIS
    # ----------------------------
    def whois_lookup(self, target):
        results = []

        try:
            w = whois.whois(target)

            fields = {
                "Domain": w.domain_name,
                "Registrar": w.registrar,
                "Creation": w.creation_date,
                "Expiration": w.expiration_date,
                "Country": w.country
            }

            for k, v in fields.items():
                if v:
                    results.append((k, str(v)))

        except Exception as e:
            results.append(("WHOIS Error", str(e)))

        return results

    # ----------------------------
    # DNS RECORDS
    # ----------------------------
    def dns_records(self, target):
        records = ["A", "AAAA", "MX", "NS", "TXT"]
        results = []

        for r in records:
            try:
                answers = dns.resolver.resolve(target, r)

                for a in answers:
                    results.append((r, str(a)))

            except:
                pass

        return results

    # ----------------------------
    # PORT SCANNER (FIXED)
    # ----------------------------
    def scan_ports(self, target, start=1, end=500):
        results = []

        try:
            ip = socket.gethostbyname(target)
        except:
            results.append(("PortScan", "Host resolve failed"))
            return results

        def scan(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)

                    result = s.connect_ex((ip, port))

                    if result == 0:
                        banner = self.banner(ip, port)
                        return (port, banner if banner else "open")

            except:
                return None

        with ThreadPoolExecutor(max_workers=100) as exe:
            futures = [exe.submit(scan, p) for p in range(start, end)]

            for f in as_completed(futures):
                r = f.result()
                if r:
                    results.append((f"Port {r[0]}", r[1]))

        return results

    # ----------------------------
    # BANNER GRABBING
    # ----------------------------
    def banner(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, port))
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024)
                return banner.decode(errors="ignore")[:80]

        except:
            return None

    # ----------------------------
    # SUBDOMAINS
    # ----------------------------
    def subdomains(self, domain):
        wordlist = ["www", "mail", "dev", "api", "test", "vpn", "portal", "admin"]
        results = []

        for w in wordlist:
            sub = f"{w}.{domain}"

            try:
                ip = socket.gethostbyname(sub)
                results.append(("Subdomain", f"{sub} -> {ip}"))
            except:
                pass

        return results

    # ----------------------------
    # WEB INFO (FIXED Web Error)
    # ----------------------------
    def web_info(self, url):

        results = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        # normalize URL
        if not url.startswith("http"):
            url = "https://" + url

        try:
            r = requests.get(url, headers=headers, timeout=10)

            results.append(("Status", r.status_code))
            results.append(("Server", r.headers.get("Server")))

            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.find("title")

            if title:
                results.append(("Title", title.text.strip()))

        except Exception as e:
            results.append(("Web Error", str(e)))

        return results

    # ----------------------------
    # DIRECTORY SCAN (FIXED)
    # ----------------------------
    def dir_scan(self, url):

        dirs = ["admin", "login", "dashboard", "backup", "config"]
        results = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        if not url.startswith("http"):
            url = "https://" + url

        for d in dirs:
            try:
                r = requests.get(url + "/" + d, headers=headers, timeout=5)

                if r.status_code in [200, 301, 302, 403]:
                    results.append(("Directory", f"/{d} -> {r.status_code}"))

            except Exception as e:
                results.append(("Dir Error", str(e)))

        return results

    # ----------------------------
    # IMAGE ANALYSIS
    # ----------------------------
    def analyze_image(self, path):
        results = []

        try:
            img = Image.open(path)
            exif = img._getexif()

            if exif:
                for tag, value in exif.items():
                    name = TAGS.get(tag, tag)
                    results.append((name, str(value)))
            else:
                results.append(("Image", "No metadata"))

        except Exception as e:
            results.append(("Image Error", str(e)))

        return results

    # ----------------------------
    # PDF ANALYSIS
    # ----------------------------
    def analyze_pdf(self, path):
        results = []

        try:
            with open(path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                meta = reader.metadata

                if meta:
                    for k, v in meta.items():
                        results.append((k, str(v)))

        except Exception as e:
            results.append(("PDF Error", str(e)))

        return results


# ==============================
# GUI
# ==============================

class InfoHunterGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("InfoHunter Ultimate")

        self.engine = ReconEngine()

        self.build_ui()

    def build_ui(self):

        frame = tk.Frame(self.root)
        frame.pack(fill="both", expand=True)

        top = tk.Frame(frame)
        top.pack(fill="x")

        self.entry = tk.Entry(top, font=("Courier", 14))
        self.entry.pack(side="left", fill="x", expand=True, padx=10, pady=10)

        tk.Button(top, text="SCAN", command=self.run_scan).pack(side="left", padx=5)
        tk.Button(top, text="Analyze File", command=self.analyze_file).pack(side="left", padx=5)
        tk.Button(top, text="Export CSV", command=self.save).pack(side="left", padx=5)

        self.tree = ttk.Treeview(frame, columns=("Field", "Value"), show="headings")
        self.tree.heading("Field", text="Field")
        self.tree.heading("Value", text="Value")
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        self.console = scrolledtext.ScrolledText(frame, height=7)
        self.console.pack(fill="x")

    def log(self, msg):
        t = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f"[{t}] {msg}\n")
        self.console.see("end")

    def run_scan(self):
        target = self.entry.get().strip()
        if not target:
            return

        self.log("Starting scan...")

        thread = threading.Thread(target=self.scan, args=(target,))
        thread.start()

    def scan(self, target):

        results = []

        results += self.engine.resolve(target)
        results += self.engine.whois_lookup(target)
        results += self.engine.dns_records(target)
        results += self.engine.subdomains(target)
        results += self.engine.scan_ports(target, 1, 300)
        results += self.engine.web_info(target)
        results += self.engine.dir_scan(target)

        self.root.after(0, lambda: self.display(results))

        self.log("Scan finished")

    def analyze_file(self):
        file = filedialog.askopenfilename()

        if not file:
            return

        if file.lower().endswith(("jpg", "jpeg", "png")):
            results = self.engine.analyze_image(file)

        elif file.lower().endswith("pdf"):
            results = self.engine.analyze_pdf(file)

        else:
            messagebox.showerror("Error", "Unsupported file")
            return

        self.display(results)

    def display(self, results):

        for i in self.tree.get_children():
            self.tree.delete(i)

        for r in results:
            self.tree.insert("", "end", values=r)

    def save(self):

        file = filedialog.asksaveasfilename(defaultextension=".csv")

        if not file:
            return

        rows = []

        for i in self.tree.get_children():
            rows.append(self.tree.item(i)["values"])

        with open(file, "w", newline="", encoding="utf8") as f:
            writer = csv.writer(f)
            writer.writerow(["Field", "Value"])
            writer.writerows(rows)


# ==============================
# MAIN
# ==============================

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("1000x700")
    app = InfoHunterGUI(root)
    root.mainloop()
