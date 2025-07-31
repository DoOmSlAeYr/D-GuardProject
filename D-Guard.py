import os
import sys
import subprocess
import requests
import re
import time
from colorama import Fore, Style, init
from pyfiglet import figlet_format

init(autoreset=True)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    clear()
    print(Fore.GREEN + figlet_format("D-Guard"))
    print(Fore.CYAN + "by DoomSlayer\n")

def input_exit(prompt):
    val = input(Fore.YELLOW + prompt + Fore.RESET).strip()
    if val.lower() in ['exit', 'quit']:
        print(Fore.GREEN + "Exiting... Stay safe!")
        sys.exit()
    return val

def add_http_scheme(url):
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def run_nmap(target, fast=True):
    print(Fore.YELLOW + f"\n[+] Scanning open TCP ports on {target} ...")
    try:
        if fast:
            ports_range = '1-1000'
            print(Fore.BLUE + "Running FAST scan (ports 1-1000)...")
        else:
            ports_range = '1-65535'
            print(Fore.BLUE + "Running SLOW and more accurate scan (all ports 1-65535)...")

        result = subprocess.run(['nmap', '-p', ports_range, '--open', '-T4', '-Pn', target],
                                capture_output=True, text=True, timeout=300)
        output = result.stdout
        ports = re.findall(r'(\d+)/tcp\s+open', output)
        if ports:
            print(Fore.GREEN + f"Open ports: {', '.join(ports)}")
            risk = "Low" if len(ports) <= 3 else "Medium" if len(ports) <= 10 else "High"
            print(Fore.CYAN + f"Risk level based on open ports: {risk}")
            return {"open_ports": ports, "risk": risk}
        else:
            print(Fore.GREEN + "No open TCP ports found.")
            return {"open_ports": [], "risk": "None"}
    except subprocess.TimeoutExpired:
        print(Fore.RED + "nmap scan timed out. Try scanning fewer ports or check network.")
        return {"open_ports": [], "risk": "Timeout"}
    except Exception as e:
        print(Fore.RED + f"nmap scan error: {e}")
        return {"open_ports": [], "risk": "Error"}

def run_sqlmap(target):
    print(Fore.YELLOW + f"\n[+] Testing for SQL Injection on {target} ...")
    try:
        result = subprocess.run(['sqlmap', '-u', target, '--batch', '--level=1', '--risk=1', '--quiet'],
                                capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr

        vulnerable = False
        risk = "None"

        if re.search(r'parameter.*is vulnerable', output, re.I) or re.search(r'web application is vulnerable', output, re.I):
            vulnerable = True
            risk = "High"
        elif "could not find any injectable parameters" in output.lower():
            vulnerable = False
            risk = "None"
        else:
            if "testing" in output.lower():
                risk = "Unknown"

        if vulnerable:
            print(Fore.RED + "SQL Injection vulnerability FOUND!")
        else:
            print(Fore.GREEN + "No SQL Injection vulnerabilities found.")

        return {"vulnerable": vulnerable, "risk": risk}
    except subprocess.TimeoutExpired:
        print(Fore.RED + "sqlmap scan timed out. Try again later or on a faster connection.")
        return {"vulnerable": False, "risk": "Timeout"}
    except Exception as e:
        print(Fore.RED + f"sqlmap scan error: {e}")
        return {"vulnerable": False, "risk": "Error"}

def test_xss(target):
    print(Fore.YELLOW + f"\n[+] Testing XSS on {target} (simple test)...")
    payload = "<script>alert(1)</script>"
    target = add_http_scheme(target)
    test_url = target
    if "?" in target:
        test_url += "&q=" + payload
    else:
        test_url += "?q=" + payload

    try:
        r = requests.get(test_url, timeout=300)
        if payload in r.text:
            print(Fore.RED + "Possible XSS vulnerability detected!")
            return True
        else:
            print(Fore.GREEN + "No XSS vulnerability detected.")
            return False
    except Exception as e:
        print(Fore.RED + f"XSS test error: {e}")
        return False

def check_http_headers(target):
    print(Fore.YELLOW + f"\n[+] Checking HTTP security headers on {target} ...")
    target = add_http_scheme(target)
    try:
        r = requests.get(target, timeout=300)
        headers = r.headers

        security_headers = {
            "Content-Security-Policy": False,
            "Strict-Transport-Security": False,
            "X-Content-Type-Options": False,
            "X-Frame-Options": False,
            "X-XSS-Protection": False,
            "Referrer-Policy": False,
            "Permissions-Policy": False
        }

        for header in security_headers.keys():
            if header in headers:
                security_headers[header] = True

        for h, present in security_headers.items():
            color = Fore.GREEN if present else Fore.RED
            status = "Present" if present else "Missing"
            print(f"{color}{h}: {status}")

        return security_headers
    except Exception as e:
        print(Fore.RED + f"HTTP headers check error: {e}")
        return {}

def full_scan(target):
    print(Fore.MAGENTA + "\nStarting FULL scan...\n")

    # Ask user for fast or slow nmap scan
    while True:
        scan_speed = input_exit("Choose nmap scan speed: (1) Fast (2) Slow (accurate): ")
        if scan_speed in ['1', '2']:
            break
        else:
            print(Fore.RED + "Invalid choice. Enter 1 or 2.")

    fast_scan = scan_speed == '1'
    nmap_res = run_nmap(target, fast=fast_scan)
    sqlmap_res = run_sqlmap(target)
    xss_res = test_xss(target)
    headers_res = check_http_headers(target)

    print(Fore.MAGENTA + "\n=== FULL SCAN SUMMARY ===")
    ports = nmap_res.get("open_ports", [])
    risk_ports = nmap_res.get("risk", "Unknown")
    print(Fore.CYAN + f"Open TCP Ports: {', '.join(ports) if ports else 'None'}")
    print(Fore.CYAN + f"Port scan risk level: {risk_ports}")

    sql_vuln = sqlmap_res.get("vulnerable", False)
    sql_risk = sqlmap_res.get("risk", "Unknown")
    print(Fore.CYAN + f"SQL Injection Vulnerability: {'Yes' if sql_vuln else 'No'}")
    print(Fore.CYAN + f"SQL Injection Risk level: {sql_risk}")

    print(Fore.CYAN + f"XSS Vulnerability: {'Yes' if xss_res else 'No'}")

    missing_headers = [h for h, present in headers_res.items() if not present]
    print(Fore.CYAN + f"Missing Security Headers: {', '.join(missing_headers) if missing_headers else 'None'}")

def main():
    banner()
    while True:
        print(Fore.YELLOW + "Choose scan type:")
        print("1) Nmap Port Scan")
        print("2) SQL Injection Scan (sqlmap)")
        print("3) XSS Test (simple)")
        print("4) HTTP Security Headers Check")
        print("5) Full Scan (All tests)")
        print("6) Exit")

        choice = input_exit("Enter option number: ")

        if choice == "1":
            target = input_exit("Enter target IP or domain: ")
            # Ask for fast or slow scan
            while True:
                speed = input_exit("Choose nmap scan speed: (1) Fast (2) Slow (accurate): ")
                if speed in ['1', '2']:
                    break
                else:
                    print(Fore.RED + "Invalid choice. Enter 1 or 2.")
            run_nmap(target, fast=(speed=='1'))

        elif choice == "2":
            target = input_exit("Enter target URL (with http/https and params): ")
            run_sqlmap(target)

        elif choice == "3":
            target = input_exit("Enter target URL (with http/https): ")
            test_xss(target)

        elif choice == "4":
            target = input_exit("Enter target URL or domain: ")
            check_http_headers(target)

        elif choice == "5":
            target = input_exit("Enter target URL or domain: ")
            full_scan(target)

        elif choice == "6":
            print(Fore.GREEN + "Goodbye!")
            break

        else:
            print(Fore.RED + "Invalid choice, try again.")

        print("\n" + "-"*50 + "\n")
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\nInterrupted by user. Exiting...")
        sys.exit(0)
