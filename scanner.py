import re
import requests
import socket
import threading
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import os

# Color codes
R, G, Y, B, M, C, W, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[97m", "\033[0m"

# Banner
def banner():
    print(f"""{M}
╔════════════════════════════════════════════════╗
║              BCF WEB SCANNER (v3.0)            ║
║           Developed by: AH-Obhi007             ║
╚════════════════════════════════════════════════╝{RESET}
""")

# PHP/Dynamic Link Finder
def php_link_finder(url, visited=None, depth=2):
    if visited is None:
        visited = set()
    if depth == 0 or url in visited:
        return []
    visited.add(url)
    found = []
    print(f"{Y}[+] Scanning: {url}{RESET}")
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all('a', href=True):
            full_url = urljoin(url, a['href'])
            if re.search(r"\.(php|asp|aspx|jsp|cfm|cgi)(\?|$)", full_url):
                if "?" in full_url:
                    print(f"{G}[✓] Found dynamic page: {full_url}{RESET}")
                    found.append(full_url)
            if urlparse(full_url).netloc == urlparse(url).netloc and full_url not in visited:
                found += php_link_finder(full_url, visited, depth-1)
    except Exception as e:
        print(f"{R}[!] Error: {e}{RESET}")
    return found

# SQL Injection Detector
def is_sqli_vulnerable(url):
    test_payload = "' OR '1'='1"
    try:
        test_url = url + (test_payload if "?" in url else f"?id={test_payload}")
        r = requests.get(test_url, timeout=5)
        errors = ['sql syntax', 'mysql_fetch', 'ORA-', 'sqlite', 'Warning', 'error in your SQL']
        if any(e.lower() in r.text.lower() for e in errors):
            return True
    except:
        return False
    return False

def sqli_scanner(url):
    print(f"{C}[+] Testing SQLi: {url}{RESET}")
    if is_sqli_vulnerable(url):
        print(f"{R}[!!!] Vulnerable to SQL Injection!{RESET}")
    else:
        print(f"{G}[✓] Not vulnerable to SQLi.{RESET}")

# XSS Vulnerability Tester
def xss_checker(url):
    payload = "<script>alert('xss')</script>"
    try:
        test_url = url + (payload if "?" in url else f"?q={payload}")
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            print(f"{R}[!!!] XSS Detected: {url}{RESET}")
        else:
            print(f"{G}[✓] No XSS vulnerability found.{RESET}")
    except Exception as e:
        print(f"{R}[!] Error: {e}{RESET}")

# Admin Panel Scanner
def admin_panel_finder(base_url):
    paths = [
        "admin", "admin/login", "admin/index", "administrator", "dashboard", "cpanel", "adminpanel",
        "systemadmin", "root", "backend", "admin_area", "admin-console"
    ]
    print(f"{Y}[+] Scanning for admin panels...{RESET}")
    for path in paths:
        full_url = urljoin(base_url + "/", path)
        try:
            r = requests.get(full_url, timeout=5)
            if r.status_code in [200, 301, 302, 403]:
                print(f"{G}[✓] Found ({r.status_code}): {full_url}{RESET}")
        except:
            continue

# Subdomain Finder
def find_subdomains(domain):
    sub_list = ['www', 'mail', 'ftp', 'webmail', 'blog', 'ns1', 'cpanel']
    found = []
    print(f"{Y}[+] Scanning for subdomains...{RESET}")
    for sub in sub_list:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            print(f"{G}[✓] Found: {subdomain}{RESET}")
            found.append(subdomain)
        except:
            continue
    return found

# Port Scanner (Fast, Threaded)
def scan_port(host, port, open_ports):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        if s.connect_ex((host, port)) == 0:
            print(f"{G}[+] Open Port: {port}{RESET}")
            open_ports.append(port)
        s.close()
    except:
        pass

def scan_ports(host):
    ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]
    open_ports = []
    threads = []
    print(f"{Y}[+] Scanning ports...{RESET}")
    for port in ports:
        t = threading.Thread(target=scan_port, args=(host, port, open_ports))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return open_ports

# Report Generator
def generate_report(domain, ports, subdomains):
    with open("BCF_Report.txt", "w") as f:
        f.write(f"--- BCF WEB SCANNER REPORT ---\nTarget: {domain}\n\n")
        f.write("Open Ports:\n")
        for p in ports:
            f.write(f"- {p}\n")
        f.write("\nSubdomains:\n")
        for s in subdomains:
            f.write(f"- {s}\n")
    print(f"{G}[✓] Report saved to BCF_Report.txt{RESET}")

# SQLi Auto Test
def find_get_params(url):
    links = []
    try:
        html = requests.get(url, timeout=5).text
        soup = BeautifulSoup(html, 'html.parser')
        for link in soup.find_all('a', href=True):
            full = urljoin(url, link['href'])
            if "?" in full:
                links.append(full)
    except:
        pass
    return links

def auto_sqli_test(base_url):
    print(f"{Y}[+] Finding parameterized URLs...{RESET}")
    targets = find_get_params(base_url)
    if not targets:
        print(f"{R}[-] No parameterized URLs found.{RESET}")
        return
    for url in targets:
        print(f"{C}[*] Testing: {url}{RESET}")
        if is_sqli_vulnerable(url):
            print(f"{R}[!!!] Vulnerable: {url}{RESET}")
        else:
            print(f"{G}[✓] Not vulnerable{RESET}")

# Clear terminal
def clear():
    os.system("cls" if os.name == "nt" else "clear")

# Menu System
def menu():
    while True:
        clear()
        banner()
        print(f"""{C}
1. PHP Link Finder
2. SQLi Scanner
3. XSS Checker
4. Admin Panel Finder
5. Subdomain Scanner
6. Port Scanner
7. Generate Report
8. SQLi Auto-Testing
0. Exit
{RESET}""")
        choice = input(f"{Y}Choose an option: {RESET}")
        if choice == "1":
            php_link_finder(input("Enter URL: "))
        elif choice == "2":
            sqli_scanner(input("Enter vulnerable URL (with ?id=): "))
        elif choice == "3":
            xss_checker(input("Enter URL (with ?q=): "))
        elif choice == "4":
            admin_panel_finder(input("Enter base URL (https://...): "))
        elif choice == "5":
            domain = input("Enter domain: ")
            subs = find_subdomains(domain)
            print(f"{C}Found Subdomains: {subs}{RESET}")
        elif choice == "6":
            scan_ports(input("Enter IP/Domain: "))
        elif choice == "7":
            target = input("Domain/IP: ")
            ports = scan_ports(target)
            subs = find_subdomains(target)
            generate_report(target, ports, subs)
        elif choice == "8":
            auto_sqli_test(input("Enter base URL: "))
        elif choice == "0":
            print(f"{G}Thanks for using BCF WEB SCANNER. Goodbye!{RESET}")
            break
        else:
            print(f"{R}Invalid choice! Try again.{RESET}")
        input(f"\n{Y}Press Enter to continue...{RESET}")

# Start
if __name__ == "__main__":
    menu()