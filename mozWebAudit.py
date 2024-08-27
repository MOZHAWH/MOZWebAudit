import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import argparse
import sys

def print_banner():
    banner = """
    ##################################################
    #                                                #
    #        _______  __      _______  ____  ____    #
    #       |  ___  ||  |    |  ___  ||  _ \|  _ \   #
    #       | |___| ||  |    | |___| || |_| | |_| |  #
    #       |  _____||  |___ |  _____||  __/|  __/   #
    #       | |      |_____||| |      | |   | |      #
    #       |_|            |___|      |_|   |_|      #
    #                                                #
    #        mozWebAudit v1.0                        #
    #        Simple Web Vulnerability Scanner        #
    #                                                #
    #        Telegram: https://t.me/MOZHAWH          #
    #                                                #
    ##################################################
    """
    print(banner)

def get_correct_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = "http://" + url  
    return url

def is_website_online(url):
    try:
        response = requests.head(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def check_website(url, output_file):
    url = get_correct_url(url)
    
    if not is_website_online(url):
        print(f"❌ The website {url} is not online. Exiting.")
        return
    
    print(f"✅ The website {url} is online. Starting analysis...\n")
    
    report = []
    detailed_report = []
    
    try:
        response = requests.get(url)
        cookies = response.cookies
        headers = response.headers
        content = response.text
        soup = BeautifulSoup(content, "html.parser")
        
        total_tests = 0
        found_issues = 0
        passed_tests = 0

        
        total_tests += 1
        if cookies:
            found_issues += 1
            report.append("Cookie Hijacking")
            detailed_report.append("The site uses cookies, which could be vulnerable to Cookie Hijacking.")
        else:
            passed_tests += 1
        
        # 2. Check for missing security headers
        headers_to_check = {
            "X-Frame-Options": "Clickjacking",
            "Content-Security-Policy": "XSS",
            "Strict-Transport-Security": "Sensitive Data Exposure",
            "X-Content-Type-Options": "MIME Sniffing",
            "Referrer-Policy": "Private URL Leakage"
        }

        for header, issue in headers_to_check.items():
            total_tests += 1
            if header not in headers:
                found_issues += 1
                report.append(issue)
                detailed_report.append(f"Missing {header} header, which could lead to {issue}.")
            else:
                passed_tests += 1

        
        total_tests += 1
        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            for inp in inputs:
                if inp.get("type") in ["text", "search"]:
                    found_issues += 1
                    report.append("SQL Injection or XSS")
                    detailed_report.append("The site has text input forms, which could be vulnerable to SQL Injection or XSS.")
                    break
        else:
            passed_tests += 1

        
        total_tests += 1
        redirects = soup.find_all("a", href=True)
        for link in redirects:
            if "http" in link['href'] and url not in link['href']:
                found_issues += 1
                report.append("Open Redirect")
                detailed_report.append("The site has external redirects, which could be vulnerable to Open Redirect attacks.")
                break
        else:
            passed_tests += 1

        
        total_tests += 1
        inline_scripts = soup.find_all("script", text=True)
        for script in inline_scripts:
            if script.string:
                found_issues += 1
                report.append("Inline Script XSS")
                detailed_report.append("The site has inline scripts, which could be vulnerable to XSS attacks.")
                break
        else:
            passed_tests += 1

        total_tests += 1
        file_uploads = soup.find_all("input", {"type": "file"})
        if file_uploads:
            found_issues += 1
            report.append("File Upload Vulnerability")
            detailed_report.append("The site has file upload forms, which could be vulnerable to File Upload vulnerabilities.")
        else:
            passed_tests += 1

        total_tests += 1
        if "SERVER_SOFTWARE" in headers:
            found_issues += 1
            report.append("Information Disclosure")
            detailed_report.append("The site reveals server software information, which could lead to Information Disclosure.")
        else:
            passed_tests += 1
        
        total_tests += 1
        if url.startswith("http://") and "Strict-Transport-Security" not in headers:
            found_issues += 1
            report.append("Man-in-the-Middle")
            detailed_report.append("The site uses HTTP without HSTS, which could lead to Man-in-the-Middle attacks.")
        else:
            passed_tests += 1
        
        total_tests += 1
        if "<iframe" in content:
            found_issues += 1
            report.append("Clickjacking (via Iframes)")
            detailed_report.append("The site uses iframes, which could be vulnerable to Clickjacking.")
        else:
            passed_tests += 1

        with open(output_file, "w") as report_file:
            report_file.write(f"URL: {url}\n")
            report_file.write(f"Total Tests Conducted: {total_tests}\n")
            report_file.write(f"Vulnerabilities Found: {found_issues}\n")
            report_file.write(f"Tests Passed: {passed_tests}\n")
            report_file.write("\nPotential Vulnerabilities:\n")
            report_file.write("\n".join(report) + "\n")
            report_file.write("\nDetailed Analysis:\n")
            report_file.write("\n".join(detailed_report) + "\n")
        
        print(f"Analysis completed. Report saved to '{output_file}'.")
    
    except requests.exceptions.RequestException as e:
        print(f"⛔ Error connecting to the site: {e}")

if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="mozWebAudit - Simple Web Vulnerability Scanner")
    parser.add_argument("url", help="The website URL to scan")
    parser.add_argument("-o", "--output", help="Specify the output file name", default="vulnerability_report.txt")

    args = parser.parse_args()

    check_website(args.url, args.output)
