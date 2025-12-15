# tools/tracenet.py

import requests
from urllib.parse import quote
import os
import re

PLATFORMS = {
    "GitHub": "https://github.com/{username}",
    "Twitter": "https://twitter.com/{username}",
    "Instagram": "https://www.instagram.com/{username}",
    "Reddit": "https://www.reddit.com/user/{username}",
    "LinkedIn": "https://www.linkedin.com/in/{username}",
    "StackOverflow": "https://stackoverflow.com/users/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Medium": "https://medium.com/@{username}",
    "Bitbucket": "https://bitbucket.org/{username}",
    "HackerOne": "https://hackerone.com/{username}",
    "Imgur": "https://imgur.com/user/{username}",
}

HEADERS = {
    "User-Agent": "PortGuardian-TraceNet/1.0 (+https://yourproject.example)"
}
REQUEST_TIMEOUT = 6


def probe_profile(username: str, platform_url: str):
    """
    Probe a platform URL for the username. Returns (found_bool, url, http_status_or_None)
    """
    url = platform_url.format(username=quote(username))
    try:
        r = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        status = r.status_code
        if status in (200, 301, 302, 403):
            return True, url, status
        return False, url, status
    except requests.RequestException:
        return False, url, None


def scan_username(username: str):
    """
    Scan all PLATFORMS for the username and return a list of result dicts.
    """
    results = []
    for name, fmt in PLATFORMS.items():
        found, url, status = probe_profile(username, fmt)
        results.append({
            "platform": name,
            "url": url,
            "found": bool(found),
            "http_status": status
        })
    return results


def hibp_breaches_for_email(email: str):
    """
    Query HaveIBeenPwned for breaches related to an email.
    Requires HIBP_API_KEY environment variable if you want a live check.
    """
    api_key = os.getenv("HIBP_API_KEY")
    if not api_key:
        return {"status": "no_api", "breaches": None}

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "PortGuardian-TraceNet/1.0"
    }
    try:
        r = requests.get(url, headers=headers, timeout=10, params={"truncateResponse": "false"})
        if r.status_code == 200:
            return {"status": "ok", "breaches": r.json()}
        if r.status_code == 404:
            return {"status": "ok", "breaches": []}
        return {"status": "error", "breaches": None}
    except requests.RequestException:
        return {"status": "error", "breaches": None}


class TraceNet:
    """
    Unified class: detect if target is email or username and run the appropriate check.
    Returns dictionary shaped for the Jinja template.
    """

    def __init__(self, target: str):
        self.target = target.strip()

    def is_email(self):
        return bool(re.match(r"[^@]+@[^@]+\.[^@]+", self.target))

    def run_recon(self):
        if self.is_email():
            result = hibp_breaches_for_email(self.target)
            return {"type": "email", "target": self.target, **result}
        else:
            results = scan_username(self.target)
            return {"type": "username", "target": self.target, "results": results}
