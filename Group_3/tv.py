import socket
import os
import sys
from datetime import datetime
import threading
import requests
from urllib.parse import urljoin
import ssl
import OpenSSL
from colorama import Fore, Back
from termcolor import colored
from pyfiglet import figlet_format

print("-" * 70)
print(Fore.CYAN +"\033[1m Time started: \033[0m" + Fore.WHITE + str(datetime.now()))

banner = os.popen('echo "\033[1m$(figlet "      S C A N O F Y")\033[0m" | lolcat --force').read()
print(banner)

target_url = input("Enter the target URL: ")
start_port = int(input("Enter the starting port number: "))
end_port = int(input("Enter the ending port number: "))
print("-" * 70)
print(Fore.LIGHTYELLOW_EX + "\033[1m Scanning Target:- \033[0m", target_url)

open_ports = []

def scan_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        conn = s.connect_ex((target_ip, port))
        if not conn:
            open_ports.append(port)
        s.close()
    except Exception as e:
        print("Error while scanning port:", e)


def scan_headers(target_url):
    try:
        response = requests.get(target_url)
        headers = response.headers

        print("-" * 70)
        print(Fore.LIGHTGREEN_EX + "\033[1m Scanning headers for vulnerabilities on \033[0m", target_url)
        print("-" * 70)

        if "X-Frame-Options" not in headers:
            print("[!] Missing X-Frame-Options header - Clickjacking vulnerability")
        if "Content-Security-Policy" not in headers:
            print("[!] Missing Content-Security-Policy header - Potential XSS vulnerability")
        if "Strict-Transport-Security" not in headers:
            print("[!] Missing Strict-Transport-Security header - Potential SSL/TLS vulnerability")

        server_header = headers.get("Server")
        if server_header:
            print("[!] Server Version Disclosure: " + server_header)

        referrer_policy = headers.get("Referrer-Policy")
        if not referrer_policy:
            print("[!] Missing Referrer-Policy header - Potential information leakage")

        set_cookie = headers.get("Set-Cookie")
        if set_cookie and "HttpOnly" not in set_cookie:
            print("[!] Missing HttpOnly flag in Set-Cookie header - Potential XSS vulnerability")
        if set_cookie and "Secure" not in set_cookie:
            print("[!] Missing Secure flag in Set-Cookie header - Potential exposure to man-in-the-middle attacks")

        if set_cookie and "SameSite=" not in set_cookie:
            print("[!] Missing SameSite attribute in Set-Cookie header - Potential CSRF vulnerability")

        access_control_allow_origin = headers.get("Access-Control-Allow-Origin")
        if not access_control_allow_origin:
            print("[!] Missing Access-Control-Allow-Origin header - Potential CORS misconfiguration")
    except Exception as e:
        print("Error while scanning headers:", e)


def search_robots_txt(target_url):
    try:
        robots_url = urljoin(target_url, "/robots.txt")
        response = requests.get(robots_url)
        if response.status_code == 200:
            print("-" * 70)
            print(Fore.BLUE + "\033[1m Robots.txt file found:- \033[0m")
            print(Fore.WHITE + response.text)
    except Exception as e:
        print("Error while searching robots.txt:", e)


# Function to check HTTP methods, TLS version, and Set-Cookies
def check_site_info(target_url):
    try:
        # Check HTTP methods
        methods = ['GET', 'POST']
        print("-" * 70)
        print(Fore.BLUE+ "\033[1m Checking enabled HTTP methods:- \033[0m")
        for method in methods:
            response = requests.request(method, target_url)
            if response.status_code != 405:
                print(Fore.WHITE + method, 'method enabled')
        
        # Get TLS version
        hostname = target_url.split('//')[-1].split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print("=" * 70)
                print(Fore.LIGHTGREEN_EX + "\033[1m TLS version: \033[0m", ssock.version())
                print("-" * 70)


        # Get SSL Certificate Expiry Date 
        hostname = target_url.split('//')[-1].split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                # Print expiry date
                print(Fore.CYAN + "\033[1m SSL certificate expiry date: \033[0m", expiry_date) 
                
        
        # Check Set-Cookies
        response = requests.get(target_url)
        cookies = response.cookies
        if cookies:
            print("=" * 70)
            print(Fore.MAGENTA + "\033[1m Set-Cookies:- \033[0m")
            for cookie in cookies:
                print(Fore.WHITE + f"{cookie.name}:- {cookie.value}")
        else:
            print("No set-cookies found.")

        print("-" * 70)
        
        
    except Exception as e:
        print("Error while checking site information:", e)


print("-" * 70)
print(Fore.LIGHTMAGENTA_EX + "\033[1m Scanning for open ports... \033[0m")

try:
    target_ip = socket.gethostbyname(target_url)
except socket.gaierror:
    print("Name resolution error")
    sys.exit()

for port in range(start_port, end_port + 1):
    thread = threading.Thread(target=scan_port, args=(port,))
    thread.start()

print("-"* 70)
print("\033[1m Port\tState\tService \033[0m")
for port in open_ports:
    try:
        service = socket.getservbyport(port)
    except:
        service = "Unknown"
    print(Fore.WHITE + f"{port}\tOpen\t{service}")


try:
    scan_headers("http://" + target_url)
    search_robots_txt("http://" + target_url)
    check_site_info("http://" + target_url)
except Exception as e:
    print("Error while scanning headers and robots.txt:", e)

def check_directory_access(target_url, directories):
    try:
        print("-" * 70)
        print(Fore.LIGHTCYAN_EX + "\033[1m Checking directory accessibility:\033[0m")
        for directory in directories:
            url = urljoin(target_url, directory)
            response = requests.get(url)
            if response.status_code == 200:
                print(Fore.WHITE + f"[+] Directory '{directory}' is accessible: {url}")
    except Exception as e:
        print("Error while checking directories:", e)

# Directories to check for accessibility
directories_to_check = ['/admin', '/panel', '/private', '/config']

try:
    check_directory_access("http://" + target_url, directories_to_check)
except Exception as e:
    print("Error while checking directories:", e)