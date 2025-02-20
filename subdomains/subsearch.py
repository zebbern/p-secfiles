#!/usr/bin/env python3

import sys
import re
import json
import time
import requests
from urllib.parse import quote

requests.packages.urllib3.disable_warnings()  # To suppress "InsecureRequestWarning" if we do verify=False

def fetch_crtsh_subdomains(domain):
    print("[*] Fetching from crt.sh...")
    url = f"https://crt.sh/?q={domain}&output=json"
    subdomains = set()
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200 and resp.text.strip():
            try:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for line in name_value.split():
                        line = line.strip().lower()
                        if line.startswith("*."):
                            line = line[2:]
                        if line:
                            subdomains.add(line)
            except json.JSONDecodeError:
                print("[WARNING] crt.sh returned non-JSON data.")
        else:
            print(f"[WARNING] crt.sh: unexpected status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] crt.sh fetch failed: {e}")
    return subdomains

def fetch_threatcrowd_subdomains(domain):
    """
    Original ThreatCrowd. We disable SSL verification due to certificate issues.
    """
    print("[*] Fetching from ThreatCrowd...")
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    subdomains = set()
    try:
        resp = requests.get(url, timeout=10, verify=False)
        if resp.status_code == 200 and resp.text.strip():
            data = resp.json()
            if isinstance(data, dict) and "subdomains" in data:
                for sd in data["subdomains"]:
                    subdomains.add(sd.lower())
        else:
            print(f"[WARNING] ThreatCrowd returned status code {resp.status_code} or empty data.")
    except Exception as e:
        print(f"[ERROR] ThreatCrowd fetch failed: {e}")
    return subdomains

def fetch_alienvault_subdomains(domain):
    print("[*] Fetching from AlienVault OTX...")
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "")
                if hostname:
                    subdomains.add(hostname.lower())
        else:
            print(f"[WARNING] AlienVault OTX: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] AlienVault OTX fetch failed: {e}")
    return subdomains

def fetch_bufferover_subdomains(domain):
    print("[*] Fetching from BufferOver DNS...")
    subdomains = set()
    url = f"https://dns.bufferover.run/dns?q={domain}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200 and resp.text.strip():
            data = resp.json()
            # FDNS_A format is "IP sub.domain.com"
            for item in data.get("FDNS_A", []):
                parts = item.split()
                if len(parts) == 2:
                    subdomains.add(parts[1].lower())
            # RDNS format is "sub.domain.com IP"
            for item in data.get("RDNS", []):
                parts = item.split()
                if len(parts) == 2:
                    subdomains.add(parts[0].lower())
        else:
            print(f"[WARNING] BufferOver: status {resp.status_code} or empty.")
    except Exception as e:
        print(f"[ERROR] BufferOver fetch failed: {e}")
    return subdomains

def fetch_hackertarget_subdomains(domain):
    print("[*] Fetching from HackerTarget...")
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200 and resp.text.strip():
            # Might return "error check your search parameter"
            if "error" not in resp.text.lower():
                lines = resp.text.splitlines()
                for line in lines:
                    parts = line.split(",")
                    if len(parts) == 2:
                        subdomains.add(parts[0].lower())
            else:
                print("[WARNING] HackerTarget responded with error.")
        else:
            print(f"[WARNING] HackerTarget: status {resp.status_code} or empty.")
    except Exception as e:
        print(f"[ERROR] HackerTarget fetch failed: {e}")
    return subdomains

# --------------------------------
# ADDITIONAL 15 (FREE) RESOURCES
# --------------------------------

def fetch_threatminer_api(domain):
    """
    1) ThreatMiner Domain API
       https://api.threatminer.org/v2/domain.php?q={domain}&rt=5
       No API key required, returns JSON with 'results' array.
    """
    print("[*] Fetching from ThreatMiner API...")
    subdomains = set()
    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            results = data.get("results", [])
            for sub in results:
                subdomains.add(sub.lower())
        else:
            print(f"[WARNING] ThreatMiner API: status {r.status_code}")
    except Exception as e:
        print(f"[ERROR] ThreatMiner API fetch failed: {e}")
    return subdomains

def fetch_rapiddns(domain):
    """
    2) RapidDNS (HTML scraping) 
       Example: https://rapiddns.io/subdomain/{domain}?full=1
       This endpoint includes subdomains in HTML table.
    """
    print("[*] Fetching from RapidDNS (HTML scrape)...")
    subdomains = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            # Very naive HTML scraping with regex
            # The results often come in a table row like: <td><a href="/subdomain/sub.example.com">sub.example.com</a></td>
            matches = re.findall(r'<td><a href="/subdomain/[^"]+">([^<]+)</a></td>', r.text, re.IGNORECASE)
            for m in matches:
                subdomains.add(m.lower())
        else:
            print(f"[WARNING] RapidDNS: status {r.status_code}")
    except Exception as e:
        print(f"[ERROR] RapidDNS fetch failed: {e}")
    return subdomains

def fetch_dnsdumpster(domain):
    """
    3) DNSDumpster (HTML scraping)
       https://dnsdumpster.com/
       We have to simulate form submission or do a GET/POST. If Cloudflare or captcha blocks us, it might fail.
    """
    print("[*] Fetching from DNSDumpster (HTML scrape)...")
    subdomains = set()
    session = requests.Session()
    try:
        # Step 1: Get csrf token
        home_resp = session.get("https://dnsdumpster.com", timeout=10)
        csrf_token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', home_resp.text)
        if not csrf_token:
            print("[WARNING] DNSDumpster: Could not find CSRF token.")
            return subdomains
        
        token = csrf_token.group(1)
        # Step 2: Post domain
        headers = {
            "Referer": "https://dnsdumpster.com",
            "User-Agent": "Mozilla/5.0",
        }
        data = {
            "csrfmiddlewaretoken": token,
            "targetip": domain
        }
        post_resp = session.post("https://dnsdumpster.com", headers=headers, data=data, timeout=10)
        
        # Step 3: Scrape subdomains from result table
        # Typically subdomains are inside table rows: <td class="col-md-4">sub.example.com</td>
        matches = re.findall(r'<td class="col-md-4">(.*?)</td>', post_resp.text, re.IGNORECASE)
        for m in matches:
            s = m.strip().lower()
            if s and " " not in s:
                subdomains.add(s)
    except Exception as e:
        print(f"[ERROR] DNSDumpster fetch failed: {e}")
    return subdomains

def fetch_wayback_machine(domain):
    """
    4) Wayback Machine (Archive.org) using the CDX Search API
       Example endpoint:
         https://web.archive.org/cdx/search?url=*.domain.com/&output=json&collapse=urlkey
    """
    print("[*] Fetching from Wayback Machine (CDX API)...")
    subdomains = set()
    # This can return big data, so we limit.
    url = f"https://web.archive.org/cdx/search?url=*.{domain}&output=json&collapse=urlkey"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200 and resp.text.strip():
            lines = resp.text.splitlines()
            # The first line is usually the header: ["original","mime","time","..."]
            for line in lines[1:]:
                parts = json.loads(line)
                original_url = parts[0]  # e.g., sub.example.com/
                # Remove protocol or trailing slash
                clean = original_url.split("/")[0].lower()
                # Might have leading "www." or other forms
                if clean.endswith(domain.lower()):
                    subdomains.add(clean)
        else:
            print(f"[WARNING] Wayback: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] Wayback Machine fetch failed: {e}")
    return subdomains

def fetch_findsubdomains(domain):
    """
    5) findsubdomains.com (HTML scraping)
       e.g. https://findsubdomains.com/subdomains-of/example.com
    """
    print("[*] Fetching from FindSubdomains (HTML scrape)...")
    subdomains = set()
    url = f"https://findsubdomains.com/subdomains-of/{domain}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            # Regex to find 'href="/subdomains-of/sub.example.com"'
            matches = re.findall(r'href="/subdomains-of/([^"]+)"', resp.text, re.IGNORECASE)
            for m in matches:
                if m.endswith(domain):
                    subdomains.add(m.lower())
        else:
            print(f"[WARNING] FindSubdomains: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] FindSubdomains fetch failed: {e}")
    return subdomains

def fetch_commoncrawl(domain):
    """
    6) Common Crawl Index (very naive approach)
       e.g. GET https://index.commoncrawl.org/CC-MAIN-2023-14-index?url=*.domain.com&output=json
       This can be huge, proceed carefully. We do a simple parse for hostnames. 
       If no data or large dataset, it might time out or be partial. 
    """
    print("[*] Fetching from Common Crawl (Index)...")
    subdomains = set()
    cc_index = "CC-MAIN-2023-14-index"  # Hard-coded example index; these rotate over time.
    query_url = f"https://index.commoncrawl.org/{cc_index}?url=*.{domain}&output=json"
    try:
        resp = requests.get(query_url, timeout=10)
        if resp.status_code == 200 and resp.text.strip():
            lines = resp.text.splitlines()
            for line in lines:
                try:
                    data = json.loads(line)
                    host = data.get("host", "").lower()
                    if host.endswith(domain.lower()):
                        subdomains.add(host)
                except:
                    pass
        else:
            print(f"[WARNING] Common Crawl: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] Common Crawl fetch failed: {e}")
    return subdomains

def fetch_suip(domain):
    """
    7) SUIP.biz DNS (HTML scraping)
       https://suip.biz/?act=dns
       Typically a form submission is required. 
       We do a naive example.
    """
    print("[*] Fetching from SUIP.biz (HTML scrape)...")
    subdomains = set()
    url = "https://suip.biz/?act=dns"
    try:
        # We'll do a single POST with the domain
        data = {
            "dns": domain,
            "submit": "dns"
        }
        resp = requests.post(url, data=data, timeout=10)
        if resp.status_code == 200:
            # Possibly a table or pre text. We'll do a naive regex for domain lines.
            # Typically shown in <div class="table table-striped table-responsive"><pre>...
            matches = re.findall(r'((?:[\w-]+\.)+%s)' % re.escape(domain), resp.text, re.IGNORECASE)
            for m in matches:
                subdomains.add(m.lower())
        else:
            print(f"[WARNING] SUIP.biz: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] SUIP.biz fetch failed: {e}")
    return subdomains

def fetch_dnstwister(domain):
    """
    8) DnsTwister.report (HTML scraping)
       Example: https://dnstwister.report/search?domain=example.com
    """
    print("[*] Fetching from DnsTwister.report (HTML scrape)...")
    subdomains = set()
    url = f"https://dnstwister.report/search?domain={domain}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            # Searching for "href="/domain/example.com" or subdomain lines
            matches = re.findall(r'/domain/([^"]+)"', resp.text, re.IGNORECASE)
            for m in matches:
                if m.lower().endswith(domain.lower()):
                    subdomains.add(m.lower())
        else:
            print(f"[WARNING] DnsTwister: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] DnsTwister fetch failed: {e}")
    return subdomains

def fetch_threatminer_html(domain):
    """
    9) ThreatMiner (HTML) alternate endpoint
       e.g. https://www.threatminer.org/host.php?q=sub.example.com
       We'll try a direct domain-based search. 
       This might be partially redundant with the JSON endpoint.
    """
    print("[*] Fetching from ThreatMiner (HTML) ...")
    subdomains = set()
    url = f"https://www.threatminer.org/domain.php?q={domain}"
    # Another route is host.php?q=somehost, but let's do domain search
    try:
        resp = requests.get(url, timeout=10, verify=False)
        if resp.status_code == 200:
            # Look for lines like <a href="domain.php?q=sub.example.com"...
            matches = re.findall(r'domain.php\?q=([^"]+)"', resp.text)
            for m in matches:
                if m.endswith(domain):
                    subdomains.add(m.lower())
        else:
            print(f"[WARNING] ThreatMiner(HTML): status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] ThreatMiner(HTML) fetch failed: {e}")
    return subdomains

def fetch_certdb(domain):
    """
    10) CertDB (HTML scraping)
        https://certdb.com/domain/<domain>
    """
    print("[*] Fetching from CertDB (HTML scrape)...")
    subdomains = set()
    url = f"https://certdb.com/domain/{domain}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            # Typically subdomains appear in a table row <td class="domain-name">sub.example.com</td>
            matches = re.findall(r'<td class="domain-name">([^<]+)</td>', resp.text, re.IGNORECASE)
            for m in matches:
                if m.endswith(domain):
                    subdomains.add(m.lower())
        else:
            print(f"[WARNING] CertDB: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] CertDB fetch failed: {e}")
    return subdomains

def fetch_ravidsearch(domain):
    """
    11) RavidSearch.org (HTML scraping example)
        Not a well-known source, but as an example to demonstrate the approach.
    """
    print("[*] Fetching from RavidSearch.org (HTML scraping example)...")
    subdomains = set()
    url = f"https://ravidsearch.org/?q={domain}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            # Just an example of looking for domain patterns
            pattern = re.compile(r'(?:[\w-]+\.)+' + re.escape(domain), re.IGNORECASE)
            for match in pattern.findall(resp.text):
                subdomains.add(match.lower())
        else:
            print(f"[WARNING] RavidSearch: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] RavidSearch fetch failed: {e}")
    return subdomains

def fetch_dnsrepo(domain):
    """
    12) DNSRepo.ninja (HTML scraping)
        https://dnsrepo.ninja/search?query=example.com
    """
    print("[*] Fetching from DNSRepo.ninja (HTML scrape)...")
    subdomains = set()
    url = f"https://dnsrepo.ninja/search?query={domain}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            # Example of naive pattern matching in returned HTML
            pattern = re.compile(r'(?:[\w-]+\.)+' + re.escape(domain), re.IGNORECASE)
            for match in pattern.findall(resp.text):
                subdomains.add(match.lower())
        else:
            print(f"[WARNING] DNSRepo: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] DNSRepo fetch failed: {e}")
    return subdomains

# 13) Chaos (ProjectDiscovery) - REQUIRES API KEY
def fetch_chaos(domain, chaos_api_key=None):
    """
    13) Chaos (ProjectDiscovery) placeholder
        https://chaos.projectdiscovery.io/#/
        This requires a free API key from ProjectDiscovery.
        If chaos_api_key is provided, we can implement it. Otherwise we skip.
    """
    print("[*] Fetching from ProjectDiscovery Chaos (requires API key)...")
    subdomains = set()
    if not chaos_api_key:
        print("[WARNING] No Chaos API key provided. Skipping.")
        return subdomains
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    headers = {"Authorization": f"Chaos {chaos_api_key}"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for sd in data.get("subdomains", []):
                subdomains.add(sd.lower())
        else:
            print(f"[WARNING] Chaos: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] Chaos fetch failed: {e}")
    return subdomains

# 14) SecurityTrails - REQUIRES API KEY
def fetch_securitytrails(domain, st_api_key=None):
    """
    14) SecurityTrails placeholder
        https://securitytrails.com/corp/apidocs
        Typically requires an API key. If provided, we can fetch subdomains easily.
    """
    print("[*] Fetching from SecurityTrails (requires API key)...")
    subdomains = set()
    if not st_api_key:
        print("[WARNING] No SecurityTrails API key provided. Skipping.")
        return subdomains
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": st_api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for sd in data.get("subdomains", []):
                # subdomains come as partial e.g. "blog", so combine
                full = f"{sd}.{domain}"
                subdomains.add(full.lower())
        else:
            print(f"[WARNING] SecurityTrails: status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] SecurityTrails fetch failed: {e}")
    return subdomains

def fetch_wayback_alternate(domain):
    """
    15) Wayback Machine (alternate method):
        Using a different set of parameters or a different approach, 
        e.g. capturing expansions from the 'Unique' lines.
    """
    print("[*] Fetching from Wayback Machine (alternate method)...")
    # We'll do a very similar approach to the other function. 
    # This is just to demonstrate a second approach or a different index/time range.
    subdomains = set()
    url = f"https://web.archive.org/cdx/search?url=*.{domain}&matchType=domain&output=json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200 and resp.text.strip():
            lines = resp.text.splitlines()
            for line in lines[1:]:
                parts = json.loads(line)
                original_url = parts[0]
                clean = original_url.split("/")[0].lower()
                if clean.endswith(domain):
                    subdomains.add(clean)
        else:
            print(f"[WARNING] Wayback (alt): status {resp.status_code}")
    except Exception as e:
        print(f"[ERROR] Wayback (alt) fetch failed: {e}")
    return subdomains

def fetch_google_dork(domain):
    """
    BONUS) Google Dorking (very naive, not recommended)
    This is likely to get you blocked or captcha-ed quickly if you do direct scraping.
    Shown here as a stub/placeholder.
    """
    print("[*] Attempting Google dork (NOT recommended for production)...")
    subdomains = set()
    # Google often blocks automated requests. We'll do a very naive approach.
    dork = f"site:*.{domain}"
    url = f"https://www.google.com/search?q={quote(dork)}"
    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }
        resp = requests.get(url, headers=headers, timeout=10)
        # If not blocked, might parse results...
        # This is typically not reliable or recommended. 
        # We'll do a naive regex:
        pattern = re.compile(r'(?:[\w-]+\.)+' + re.escape(domain), re.IGNORECASE)
        for match in pattern.findall(resp.text):
            subdomains.add(match.lower())
    except Exception as e:
        print(f"[ERROR] Google dork fetch failed (likely blocked/CAPTCHA): {e}")
    return subdomains

# --------------------------------
# MAIN
# --------------------------------

def main():
    if len(sys.argv) < 2:
        domain = input("Enter domain (e.g., example.com): ").strip()
    else:
        domain = sys.argv[1].strip()

    # OPTIONAL: Provide your API keys if you have them
    CHAOS_API_KEY = None  # e.g. "abcd1234"
    SECURITYTRAILS_API_KEY = None  # e.g. "xyz123"

    print(f"\n=== MASS SUBDOMAIN ENUMERATION FOR: {domain} ===\n")

    all_subs = set()

    # Original 5 sources
    all_subs.update(fetch_crtsh_subdomains(domain))
    all_subs.update(fetch_threatcrowd_subdomains(domain))
    all_subs.update(fetch_alienvault_subdomains(domain))
    all_subs.update(fetch_bufferover_subdomains(domain))
    all_subs.update(fetch_hackertarget_subdomains(domain))

    # Additional 15 sources
    all_subs.update(fetch_threatminer_api(domain))
    all_subs.update(fetch_rapiddns(domain))
    all_subs.update(fetch_dnsdumpster(domain))
    all_subs.update(fetch_wayback_machine(domain))
    all_subs.update(fetch_findsubdomains(domain))
    all_subs.update(fetch_commoncrawl(domain))
    all_subs.update(fetch_suip(domain))
    all_subs.update(fetch_dnstwister(domain))
    all_subs.update(fetch_threatminer_html(domain))
    all_subs.update(fetch_certdb(domain))
    all_subs.update(fetch_ravidsearch(domain))
    all_subs.update(fetch_dnsrepo(domain))
    all_subs.update(fetch_chaos(domain, CHAOS_API_KEY))           # Key needed
    all_subs.update(fetch_securitytrails(domain, SECURITYTRAILS_API_KEY))  # Key needed
    all_subs.update(fetch_wayback_alternate(domain))

    # Bonus (Google Dork) - typically blocked
    # all_subs.update(fetch_google_dork(domain))

    # Clean up & sort
    final_subdomains = sorted(s for s in all_subs if s.endswith(domain))
    
    print("\n[*] Unique subdomains found:\n")
    for sub in final_subdomains:
        print(sub)

    # Save results
    output_file = "final_subdomains.txt"
    with open(output_file, "w") as f:
        for sub in final_subdomains:
            f.write(sub + "\n")

    print(f"\n[*] Results saved to: {output_file}\n")


if __name__ == "__main__":
    main()
