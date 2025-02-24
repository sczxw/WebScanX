#!/usr/bin/env python3



import requests

import dns.resolver

from wafw00f.main import WAFW00F

from colorama import Fore, Style, init

from Wappalyzer import Wappalyzer, WebPage

import warnings

from concurrent.futures import ThreadPoolExecutor, as_completed

import threading

import os

import re



# Initialize colorama

init(autoreset=True)



# Suppress Wappalyzer warnings

warnings.filterwarnings("ignore", category=UserWarning)



# Thread-safe data structures

subdomains_lock = threading.Lock()

directories_lock = threading.Lock()



def print_banner():

    """Display the tool banner."""

    banner = f"""

{Fore.BLUE} __      __      ___.     _________                    ____  ___

{Fore.BLUE}/  \\    /  \\ ____\\_ |__  /   _____/ ____ _____    ____ \\   \\/  /

{Fore.BLUE}\\   \\/\\/   // __ \\| __ \\ \\_____  \\_/ ___\\\\__  \\  /    \\ \\     / 

{Fore.BLUE} \\        /\\  ___/| \\_\\ \\/        \\  \\___ / __ \\|   |  \\/     \\ 

{Fore.BLUE}  \\__/\\  /  \\___  >___  /_______  /\\___  >____  /___|  /___/\\  \\

{Fore.BLUE}       \\/       \\/    \\/        \\/     \\/     \\/     \\/      \\_/

{Fore.MAGENTA}WebScanX - Comprehensive Web Scanning Tool By sczxw.

{Fore.CYAN}Scan domains for subdomains, technologies, files, WAFs, and directories.

{Fore.BLUE}=========================================={Style.RESET_ALL}

    """

    print(banner)



def validate_domain(domain):

    """Validate the domain name."""

    # Regex to match a valid domain name (including optional http:// or https://)

    domain_regex = re.compile(

        r"^(https?:\/\/)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    )

    return bool(domain_regex.match(domain))



def validate_wordlist_file(file_path):

    """Validate the wordlist file."""

    if not file_path:  # If no file is provided, use the default wordlist

        return True

    return os.path.isfile(file_path)



def validate_yes_no(input_str):

    """Validate yes/no input."""

    return input_str.lower() in ["yes", "no"]



def find_subdomains(domain, wordlist=None):

    """Find subdomains using a wordlist (multi-threaded) and validate HTTP responses."""

    subdomains = set()

    wordlist = wordlist or ["www", "mail", "ftp", "test", "api", "dev", "admin"]



    def check_subdomain(sub):

        full_domain = f"{sub}.{domain}"

        try:

            # Step 1: Check DNS resolution

            try:

                dns.resolver.resolve(full_domain, 'A')

            except dns.resolver.NXDOMAIN:

                return  # Skip subdomains that don't exist

            except dns.resolver.NoAnswer:

                return  # Skip subdomains without DNS records

            except dns.resolver.Timeout:

                return  # Skip subdomains that time out



            # Step 2: Check HTTPS first, then HTTP if HTTPS fails

            headers = {

                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

            }

            try:

                # Try HTTPS first

                url = f"https://{full_domain}"

                response = requests.get(url, headers=headers, timeout=5)

                if response.status_code in [200, 301, 302, 403, 500]:

                    with subdomains_lock:

                        subdomains.add(full_domain)

            except requests.exceptions.SSLError:

                # If HTTPS fails, try HTTP

                try:

                    url = f"http://{full_domain}"

                    response = requests.get(url, headers=headers, timeout=5)

                    if response.status_code in [200, 301, 302, 403, 500]:

                        with subdomains_lock:

                            subdomains.add(full_domain)

                except requests.exceptions.RequestException:

                    pass  # Skip subdomains that don't respond to HTTP requests

            except requests.exceptions.RequestException:

                pass  # Skip subdomains that don't respond to HTTPS requests

        except Exception as e:

            print(f"{Fore.RED}Error checking {full_domain}: {e}{Style.RESET_ALL}")



    # Use ThreadPoolExecutor for multi-threading

    with ThreadPoolExecutor(max_workers=10) as executor:

        futures = [executor.submit(check_subdomain, sub) for sub in wordlist]

        for future in as_completed(futures):

            future.result()  # Wait for threads to complete



    return list(subdomains)



def detect_technologies(url):

    """Detect all technologies and group them by category."""

    try:

        wappalyzer = Wappalyzer.latest()

        webpage = WebPage.new_from_url(url)

        technologies = wappalyzer.analyze_with_versions_and_categories(webpage)



        # Map categories to human-readable names

        category_map = {

            "web-servers": "Web Servers",

            "programming-languages": "Programming Languages",

            "javascript-frameworks": "JavaScript Frameworks",

            "cms": "Content Management Systems",

            "analytics": "Analytics Tools",

            "caching": "Caching Tools",

            "cdn": "Content Delivery Networks",

            "databases": "Databases",

            "operating-systems": "Operating Systems",

            "security": "Security Tools",

        }



        # Group technologies by category

        categorized_technologies = {}

        for tech, details in technologies.items():

            # Extract categories and versions

            categories = details.get("categories", [])

            versions = details.get("versions", [])

            version = ", ".join(versions) if versions else "Couldn't detect"



            # Map categories to human-readable names

            for cat in categories:

                readable_cat = category_map.get(cat, cat)

                if readable_cat not in categorized_technologies:

                    categorized_technologies[readable_cat] = []

                categorized_technologies[readable_cat].append(f"{tech} (Version: {version})")



        return categorized_technologies

    except Exception as e:

        print(f"{Fore.RED}Error detecting technologies: {e}{Style.RESET_ALL}")

        return {}



def check_files(url):

    files = ["robots.txt", "security.txt", ".well-known/security.txt"]

    found_files = {}

    headers = {

        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    }

    for file in files:

        try:

            # Try HTTPS first

            full_url = f"{url}/{file}"

            response = requests.get(full_url, headers=headers, timeout=5)

            if response.status_code == 200:

                found_files[file] = f"{Fore.GREEN}Found{Style.RESET_ALL}"

            elif response.status_code == 404:

                found_files[file] = f"{Fore.RED}Not Found{Style.RESET_ALL}"

            else:

                found_files[file] = f"{Fore.YELLOW}Status Code: {response.status_code}{Style.RESET_ALL}"

        except requests.exceptions.SSLError:

            # If HTTPS fails, try HTTP

            try:

                full_url = f"{url.replace('https://', 'http://')}/{file}"

                response = requests.get(full_url, headers=headers, timeout=5)

                if response.status_code == 200:

                    found_files[file] = f"{Fore.GREEN}Found{Style.RESET_ALL}"

                elif response.status_code == 404:

                    found_files[file] = f"{Fore.RED}Not Found{Style.RESET_ALL}"

                else:

                    found_files[file] = f"{Fore.YELLOW}Status Code: {response.status_code}{Style.RESET_ALL}"

            except requests.exceptions.RequestException as e:

                found_files[file] = f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}"

        except requests.exceptions.RequestException as e:

            found_files[file] = f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}"

    return found_files



def detect_waf(url):

    """Detect WAF using WafW00F."""

    waf_detector = WAFW00F(url)

    waf = waf_detector.identwaf()

    if waf:

        return waf

    else:

        return "No WAF detected"

def bruteforce_directories(url, wordlist=None): 

    """ 

    Bruteforce common directories using a wordlist (multi-threaded). 

    Only directories with a status code of 200 (Found) are displayed. 

    """ 

    if wordlist is None: 

        wordlist = ["admin", "login", "wp-admin", "dashboard", "test", "api", "backup", "config", "assets", "images"] 



    headers = { 

        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" 

    } 



    # Track discovered directories 

    discovered_dirs = [] 



    def check_directory(directory): 

        full_url = f"{url}/{directory}" 

        try: 

            # Try HTTPS first 

            response = requests.get(full_url, headers=headers, timeout=5) 

            if response.status_code == 200: 

                with directories_lock: 

                    discovered_dirs.append(full_url) 

                    print(f"{Fore.GREEN}  - {full_url}: Found{Style.RESET_ALL}") 

        except requests.exceptions.SSLError: 

            # If HTTPS fails, try HTTP 

            try: 

                full_url = f"{url.replace('https://', 'http://')}/{directory}" 

                response = requests.get(full_url, headers=headers, timeout=5) 

                if response.status_code == 200: 

                    with directories_lock: 

                        discovered_dirs.append(full_url) 

                        print(f"{Fore.GREEN}  - {full_url}: Found{Style.RESET_ALL}") 

            except requests.exceptions.RequestException: 

                pass  # Skip errors and continue with the next directory 

        except requests.exceptions.RequestException: 

            pass  # Skip errors and continue with the next directory 



    # Use ThreadPoolExecutor for multi-threading 

    with ThreadPoolExecutor(max_workers=20) as executor: 

        futures = [executor.submit(check_directory, directory) for directory in wordlist] 

        for future in as_completed(futures): 

            future.result()  # Wait for threads to complete 



    # Print summary of discovered directories 

    if discovered_dirs: 

        print(f"\n{Fore.GREEN}[+] Discovered Directories:{Style.RESET_ALL}") 

        for dir in discovered_dirs: 

            print(f"  - {dir}") 

    else: 

        print(f"\n{Fore.RED}[+] No directories discovered.{Style.RESET_ALL}")





def strip_ansi_codes(text):

    """Remove ANSI color codes from a string."""

    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    return ansi_escape.sub("", text)



def save_results(results, filename="results.txt"):

    """Save results to a text file in a human-readable format."""

    with open(filename, "w") as f:

        # Write domain information

        f.write(f"Domain: {results.get('domain', 'N/A')}\n")

        f.write("\n")



        # Write subdomains

        f.write("Subdomains:\n")

        subdomains = results.get("subdomains", [])

        if subdomains:

            for subdomain in subdomains:

                f.write(f"  - {subdomain}\n")

        else:

            f.write("  No subdomains found.\n")

        f.write("\n")



        # Write technologies

        f.write("Technologies:\n")

        technologies = results.get("technologies", {})

        if technologies:

            for category, tech_list in technologies.items():

                f.write(f"{category}:\n")

                for tech in tech_list:

                    f.write(f"  - {strip_ansi_codes(tech)}\n")  # Strip ANSI codes

        else:

            f.write("  No technologies detected.\n")

        f.write("\n")



        # Write files

        f.write("Files:\n")

        files = results.get("files", {})

        if files:

            for file, status in files.items():

                f.write(f"  - {file}: {strip_ansi_codes(status)}\n")  # Strip ANSI codes

        else:

            f.write("  No files found.\n")

        f.write("\n")



        # Write WAF

        f.write("WAF:\n")

        waf = results.get("waf", "N/A")

        f.write(f"  - {strip_ansi_codes(waf)}\n")  # Strip ANSI codes

        f.write("\n")



    print(f"\n{Fore.CYAN}[+] Results saved to {filename}{Style.RESET_ALL}")



def main():

    print_banner()



    # Take user input for the domain

    while True:

        domain = input(f"{Fore.YELLOW}Enter the domain to scan (e.g., example.com): {Style.RESET_ALL}").strip()

        if validate_domain(domain):

            break

        else:

            print(f"{Fore.RED}Invalid Input: Please enter a valid domain name.{Style.RESET_ALL}")



    # Take user input for the wordlist file (for subdomains)

    while True:

        wordlist_file = input(f"{Fore.YELLOW}Enter the path to a custom wordlist file for subdomains (or press Enter to use the default): {Style.RESET_ALL}").strip()

        if validate_wordlist_file(wordlist_file):

            break

        else:

            print(f"{Fore.RED}Invalid Input: Wordlist file not found. Please provide a valid file path.{Style.RESET_ALL}")



    # Load the wordlist if provided

    wordlist = None

    if wordlist_file:

        try:

            with open(wordlist_file, "r") as f:

                wordlist = [line.strip() for line in f if line.strip()]

            print(f"{Fore.GREEN}[+] Using custom wordlist: {wordlist_file}{Style.RESET_ALL}")

        except FileNotFoundError:

            print(f"{Fore.RED}Error: Wordlist file not found. Using default wordlist.{Style.RESET_ALL}")

    else:

        print(f"{Fore.GREEN}[+] Using default wordlist for subdomains.{Style.RESET_ALL}")



    # Take user input for the directory bruteforcing wordlist

    while True:

        dir_wordlist_file = input(f"{Fore.YELLOW}Enter the path to a custom wordlist file for directory bruteforcing (or press Enter to use the default): {Style.RESET_ALL}").strip()

        if validate_wordlist_file(dir_wordlist_file):

            break

        else:

            print(f"{Fore.RED}Invalid Input: Wordlist file not found. Please provide a valid file path.{Style.RESET_ALL}")



    # Load the directory bruteforcing wordlist if provided

    dir_wordlist = None

    if dir_wordlist_file:

        try:

            with open(dir_wordlist_file, "r") as f:

                dir_wordlist = [line.strip() for line in f if line.strip()]

            print(f"{Fore.GREEN}[+] Using custom wordlist for directory bruteforcing: {dir_wordlist_file}{Style.RESET_ALL}")

        except FileNotFoundError:

            print(f"{Fore.RED}Error: Wordlist file not found. Using default wordlist for directory bruteforcing.{Style.RESET_ALL}")

    else:

        print(f"{Fore.GREEN}[+] Using default wordlist for directory bruteforcing.{Style.RESET_ALL}")



    # Ensure the domain starts with 'http://' or 'https://'

    if not domain.startswith(('http://', 'https://')):

        url = f"https://{domain}"  # Default to HTTPS if no protocol is specified

    else:

        url = domain



    print(f"\n{Fore.CYAN}[+] Scanning domain: {url}{Style.RESET_ALL}")



    print(f"\n{Fore.BLUE}[+] Finding subdomains...{Style.RESET_ALL}")

    subdomains = find_subdomains(domain, wordlist)

    if subdomains:

        print(f"{Fore.GREEN}Subdomains found: {Style.RESET_ALL}{subdomains}")

    else:

        print(f"{Fore.RED}No subdomains found.{Style.RESET_ALL}")



    print(f"\n{Fore.BLUE}[+] Detecting web technologies...{Style.RESET_ALL}")

    technologies = detect_technologies(url)

    if technologies:

        for category, tech_list in technologies.items():

            print(f"{Fore.GREEN}{category}: {Style.RESET_ALL}")

            for tech in tech_list:

                print(f"  - {tech}")

    else:

        print(f"{Fore.RED}No technologies detected.{Style.RESET_ALL}")



    print(f"\n{Fore.BLUE}[+] Checking for important files...{Style.RESET_ALL}")

    files = check_files(url)

    for file, status in files.items():

        print(f"{Fore.YELLOW}{file}: {Style.RESET_ALL}{status}")



    print(f"\n{Fore.BLUE}[+] Detecting WAF...{Style.RESET_ALL}")

    waf = detect_waf(url)

    print(f"{Fore.GREEN}WAF detected: {Style.RESET_ALL}{waf}")



    print(f"\n{Fore.BLUE}[+] Bruteforcing directories...{Style.RESET_ALL}")

    bruteforce_directories(url, dir_wordlist)



    # Ask the user if they want to save the results

    while True:

        save_option = input(f"{Fore.YELLOW}Do you want to save the results to a file? (yes/no): {Style.RESET_ALL}").strip().lower()

        if validate_yes_no(save_option):

            break

        else:

            print(f"{Fore.RED}Invalid Input: Please enter 'yes' or 'no'.{Style.RESET_ALL}")



    if save_option == "yes":

        filename = input(f"{Fore.YELLOW}Enter the name of the results file (e.g., output.txt, or press Enter for default): {Style.RESET_ALL}").strip()

        if not filename:

            filename = "results.txt"  # Default file name



        # Save results to the specified file

        results = {

            "domain": domain,

            "subdomains": subdomains,

            "technologies": technologies,

            "files": files,

            "waf": waf

        }

        save_results(results, filename)

    else:

        print(f"{Fore.CYAN}[+] Results not saved.{Style.RESET_ALL}")



if __name__ == "__main__":

    main()

