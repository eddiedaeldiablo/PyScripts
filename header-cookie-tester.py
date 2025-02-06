import requests
import socket

# ANSI color codes
GREEN = "\033[92m"  # Green for enabled headers/cookies
RED = "\033[91m"  # Red for missing/insecure headers/cookies
RESET = "\033[0m"  # Reset color

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Ensures HTTPS is enforced",
    "Content-Security-Policy": "Prevents XSS attacks",
    "X-Frame-Options": "Mitigates Clickjacking",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Referrer-Policy": "Controls referrer leakage",
    "Permissions-Policy": "Restricts browser features",
    "Access-Control-Allow-Origin": "CORS configuration",
    "X-XSS-Protection": "Provides basic XSS protection"
}

# Check for missing or insecure headers based on OWASP/SANS
def check_headers(response):
    print("\n[INFO] Checking Security Headers...\n")
    missing_headers = []
    enabled_headers = []
    
    for header, description in SECURITY_HEADERS.items():
        if header not in response.headers:
            missing_headers.append(f"{RED}{header} - {description}{RESET}")
            print(f"{RED}[MISSING] {header} - {description}{RESET}")
        else:
            header_value = response.headers[header]
            enabled_headers.append(f"{GREEN}{header} - {header_value}{RESET}")
            print(f"{GREEN}[ENABLED] {header} - {header_value}{RESET}")
    
    return missing_headers, enabled_headers

# Check for insecure cookies and show all cookie parameters
def check_cookies(response):
    print("\n[INFO] Checking Cookies...\n")
    insecure_cookies = []
    secure_cookies = []
    
    # Debugging: Print out the raw cookies from the response
    print(f"{GREEN}Cookies from {response.url}: {response.cookies}{RESET}")
    
    if not response.cookies:
        print(f"{RED}No cookies found in the response from {response.url}{RESET}")
    
    for cookie in response.cookies:
        issues = []
        cookie_flags = []
        
        # Gather all cookie parameters
        cookie_details = {
            "Name": cookie.name,
            "Value": cookie.value,
            "Domain": cookie.domain,
            "Path": cookie.path,
            "Expires": cookie.expires if cookie.expires else "Not Set",
            "Secure": cookie.secure,
            "HttpOnly": cookie.has_nonstandard_attr("HttpOnly"),
            "SameSite": cookie._rest.get("SameSite", "Not Set")  # SameSite might not be set explicitly
        }
        
        # Check for security flags
        if not cookie.secure:
            issues.append("Secure flag missing")
        else:
            cookie_flags.append("Secure")
        
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("HttpOnly flag missing")
        else:
            cookie_flags.append("HttpOnly")
        
        if "SameSite" not in cookie._rest.keys():
            issues.append("SameSite flag missing")
        else:
            cookie_flags.append(f"SameSite={cookie._rest['SameSite']}")
        
        # Display the cookie's details
        if issues:
            insecure_cookies.append(f"{RED}{cookie.name} - {', '.join(issues)}{RESET}")
            print(f"{RED}[INSECURE] {cookie.name} - {', '.join(issues)}{RESET}")
        else:
            secure_cookies.append(f"{GREEN}{cookie.name} - {', '.join(cookie_flags)}{RESET}")
            print(f"{GREEN}[SECURE] {cookie.name} - {', '.join(cookie_flags)}{RESET}")
        
        # Show all cookie details
        print(f"{GREEN}Cookie Details for {cookie.name}:{RESET}")
        for param, value in cookie_details.items():
            print(f"    {param}: {value}")
    
    return insecure_cookies, secure_cookies

# Function to get FQDN (Fully Qualified Domain Name) for a domain
def get_fqdn(domain):
    try:
        fqdn = socket.gethostbyname(domain)
        return fqdn
    except socket.gaierror:
        return None

# Scan a target URL
def scan_website(target_url):
    print(f"\n[INFO] Scanning: {target_url}\n")
    try:
        # Ensure the website is using HTTPS
        if not target_url.startswith("https://"):
            print(f"{RED}[WARNING] {target_url} is not using HTTPS!{RESET}")
        
        response = requests.get(target_url, allow_redirects=True, timeout=10)
        
        # Check for common error codes (4xx, 5xx)
        if response.status_code >= 400 and response.status_code < 500:
            print(f"{RED}[ERROR] Client-side error ({response.status_code}) - Check the URL.{RESET}")
            return
        elif response.status_code >= 500:
            print(f"{RED}[ERROR] Server-side error ({response.status_code}) - Try again later.{RESET}")
            return
        
        # Get FQDN
        fqdn = get_fqdn(target_url)
        if fqdn:
            print(f"{GREEN}FQDN for {target_url}: {fqdn}{RESET}")
        else:
            print(f"{RED}Unable to resolve FQDN for {target_url}{RESET}")
        
        missing_headers, enabled_headers = check_headers(response)
        insecure_cookies, secure_cookies = check_cookies(response)
        
        # Summary
        print("\n[SUMMARY] Security Audit for:", target_url)
        if not missing_headers and not insecure_cookies:
            print(f"{GREEN}[OK] No major security issues found!{RESET}")
        else:
            if missing_headers:
                print(f"{RED}[WARNING] {len(missing_headers)} Missing Security Headers:{RESET}")
                for header in missing_headers:
                    print(f"    - {header}")
            if enabled_headers:
                print(f"{GREEN}[INFO] {len(enabled_headers)} Enabled Security Headers:{RESET}")
                for header in enabled_headers:
                    print(f"    - {header}")
            
            if insecure_cookies:
                print(f"{RED}[WARNING] {len(insecure_cookies)} Insecure Cookies Found:{RESET}")
                for cookie in insecure_cookies:
                    print(f"    - {cookie}")
            if secure_cookies:
                print(f"{GREEN}[INFO] {len(secure_cookies)} Secure Cookies:{RESET}")
                for cookie in secure_cookies:
                    print(f"    - {cookie}")

    except requests.RequestException as e:
        print(f"{RED}[ERROR] Error scanning {target_url}: {e}{RESET}")

def get_domains():
    """Ask the user for multiple domains."""
    domains = input("Enter target websites (comma-separated, e.g., https://example.com, https://test.com): ").strip().split(',')
    return [domain.strip() for domain in domains if domain.strip()]

if __name__ == "__main__":
    target_domains = get_domains()
    for domain in target_domains:
        scan_website(domain)
