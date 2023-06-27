import re
import requests
import argparse
import http.client
from html import unescape

# Disable SSL certificate verification
requests.packages.urllib3.disable_warnings()

# Set the desired user agent
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36"

# Create an argument parser
parser = argparse.ArgumentParser(description="WordPress plugin and theme version extractor")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--url", help="URL of the target WordPress website")
group.add_argument("--file", help="Path to a file containing URLs (one URL per line)")
args = parser.parse_args()

# Remove trailing slash from the URL if provided
if args.url:
    args.url = args.url.rstrip("/")

# Create a session with a custom user agent
session = requests.Session()
session.headers.update({"User-Agent": user_agent})

# Function to extract version from a given file URL
def extract_version(file_url):
    try:
        response = session.get(file_url, verify=False)
        if response.status_code in (404, 401, 403):
            return "Unable to read"
        version_match = re.search(r'(?:Stable tag|Version):\s*([0-9.]+)', response.text, re.IGNORECASE)
        version = version_match.group(1) if version_match else "Unknown"
        # Validate version format
        if re.match(r'^\d+(?:\.\d+){0,5}$', version):
            return version
    except (requests.exceptions.RequestException, http.client.RemoteDisconnected, requests.exceptions.ProxyError):
        pass
    return "Unknown"

# Generate Wordfence URL for plugin or theme
def generate_wordfence_url(slug, is_plugin):
    if is_plugin:
        return f"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/{slug}/"
    else:
        return f"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-themes/{slug}/"

# Generate Wpscan URL for plugin or theme
def generate_wpscan_url(slug, is_plugin):
    if is_plugin:
        return f"https://wpscan.com/plugin/{slug}/"
    else:
        return f"https://wpscan.com/theme/{slug}/"

# Process a single URL
def process_url(url):
     try:
        response = session.get(url, verify=False,timeout=20)
        plugin_slugs = set(re.findall(r'wp-content/plugins/([^/]+)/', response.text))
        theme_slugs = set(re.findall(r'wp-content/themes/([^/]+)/', response.text))

        processed_themes = set()  # Track processed themes

        # Process plugin slugs
        for plugin_slug in plugin_slugs:
           readme_url = f"{url}/wp-content/plugins/{plugin_slug}/readme.txt"
           plugin_version = extract_version(readme_url)
           wordfence_url = generate_wordfence_url(plugin_slug, True)
           wpscan_url = generate_wpscan_url(plugin_slug, True)

           print(f"Plugin: {unescape(plugin_slug)}, Version: {unescape(plugin_version)}")
           print(f"Readme.txt: {unescape(readme_url)}")
           print(f"Wordfence: {unescape(wordfence_url)}")
           print(f"Wpscan: {unescape(wpscan_url)}")
           print()

        # Process theme slugs
        for theme_slug in theme_slugs:
           if '}' not in theme_slug and theme_slug not in processed_themes:
               style_url = f"{url}/wp-content/themes/{theme_slug}/style.css"
               theme_version = extract_version(style_url)
               wordfence_url = generate_wordfence_url(theme_slug, False)
               wpscan_url = generate_wpscan_url(theme_slug, False)

               print(f"Theme: {unescape(theme_slug)}, Version: {unescape(theme_version)}")
               print(f"Style.css: {unescape(style_url)}")
               print(f"Wordfence: {unescape(wordfence_url)}")
               print(f"Wpscan: {unescape(wpscan_url)}")
               print()

               processed_themes.add(theme_slug)
     except:
       pass

# Check if a file is provided
if args.file:
    with open(args.file, "r") as file:
        for line in file:
            url = line.strip()
            if url:
                url = url.rstrip("/")
                process_url(url)
                print()
else:
    process_url(args.url)
