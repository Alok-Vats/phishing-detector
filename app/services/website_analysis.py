"""Static Website/HTML Analysis Service with strict SSRF protections."""

from __future__ import annotations

import socket
import threading
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser

MAX_RESPONSE_SIZE = 1024 * 1024 * 2  # 2MB
TIMEOUT_SECONDS = 5
ALLOWED_CONTENT_TYPES = ["text/html", "application/xhtml+xml", "text/plain"]

_original_getaddrinfo = socket.getaddrinfo
_dns_pinning = threading.local()

def _safe_getaddrinfo(*args, **kwargs):
    host = args[0]
    pinned_ips = getattr(_dns_pinning, 'pinned_ips', {})
    if host in pinned_ips:
        ip = pinned_ips[host]
        port = args[1]
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
        return [(family, socket.SOCK_STREAM, 6, '', sockaddr)]
    return _original_getaddrinfo(*args, **kwargs)

if socket.getaddrinfo is not _safe_getaddrinfo:
    socket.getaddrinfo = _safe_getaddrinfo


class WebsiteAnalyzer(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.parsed_base = urllib.parse.urlparse(base_url)
        
        self.has_login_form = False
        self.has_password_field = False
        self.has_hidden_elements = False
        self.suspicious_form_destinations = []
        self.external_iframes = []
        self.external_scripts = []
        self.external_links = []
        self.total_links = 0
        
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        
        if tag == "form":
            action = attr_dict.get("action", "")
            self._current_form = action
            
            # Check form destination
            if action:
                parsed_action = urllib.parse.urlparse(urllib.parse.urljoin(self.base_url, action))
                if parsed_action.netloc and parsed_action.netloc != self.parsed_base.netloc:
                    self.suspicious_form_destinations.append(action)

        elif tag == "input":
            input_type = attr_dict.get("type", "").lower()
            if input_type == "password":
                self.has_password_field = True
                if self._current_form is not None:
                    self.has_login_form = True
            elif input_type == "hidden":
                self.has_hidden_elements = True

        elif tag == "iframe":
            src = attr_dict.get("src", "")
            if src:
                parsed_src = urllib.parse.urlparse(urllib.parse.urljoin(self.base_url, src))
                if parsed_src.netloc and parsed_src.netloc != self.parsed_base.netloc:
                    self.external_iframes.append(src)

        elif tag == "script":
            src = attr_dict.get("src", "")
            if src:
                parsed_src = urllib.parse.urlparse(urllib.parse.urljoin(self.base_url, src))
                if parsed_src.netloc and parsed_src.netloc != self.parsed_base.netloc:
                    self.external_scripts.append(src)

        elif tag == "a":
            self.total_links += 1
            href = attr_dict.get("href", "")
            if href:
                parsed_href = urllib.parse.urlparse(urllib.parse.urljoin(self.base_url, href))
                if parsed_href.netloc and parsed_href.netloc != self.parsed_base.netloc:
                    self.external_links.append(href)

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None


def get_and_validate_ip(hostname: str) -> str | None:
    """Resolve and check ALL IPs to prevent SSRF. Returns a safe IP to pin."""
    try:
        infos = _original_getaddrinfo(hostname, 80)
        safe_ip = None
        for info in infos:
            ip = info[4][0]
            ip_obj = ipaddress.ip_address(ip)
            # Strict internal range checks
            if (ip_obj.is_private or ip_obj.is_loopback or 
                ip_obj.is_link_local or ip_obj.is_multicast or 
                ip_obj.is_unspecified or ip_obj.is_reserved):
                return None # Fail closed if ANY IP is internal
            
            if not safe_ip:
                safe_ip = ip
        return safe_ip
    except (socket.gaierror, ValueError, IndexError):
        return None


def fetch_and_analyze(url: str) -> dict | None:
    """Safely fetch HTML and return static analysis signals. Returns None if unavailable/unsafe."""
    parsed_url = urllib.parse.urlparse(url)
    
    if parsed_url.scheme not in ("http", "https"):
        return None
        
    if not parsed_url.hostname:
        return None

    # SSRF Protection with DNS Pinning (TOCTOU mitigation)
    pinned_ip = get_and_validate_ip(parsed_url.hostname)
    if not pinned_ip:
        return {"error": "ssrf_protection_blocked_internal_ip"}

    if not hasattr(_dns_pinning, 'pinned_ips'):
        _dns_pinning.pinned_ips = {}
        
    _dns_pinning.pinned_ips[parsed_url.hostname] = pinned_ip

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    )
    
    try:
        # Custom redirect handling to prevent redirects to internal IPs with DNS pinning
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                parsed_new = urllib.parse.urlparse(newurl)
                if parsed_new.hostname:
                    redirect_ip = get_and_validate_ip(parsed_new.hostname)
                    if not redirect_ip:
                        raise urllib.error.URLError("Redirected to internal IP (SSRF Protection)")
                    _dns_pinning.pinned_ips[parsed_new.hostname] = redirect_ip
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        opener = urllib.request.build_opener(NoRedirectHandler)
        urllib.request.install_opener(opener)

        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            content_type = response.headers.get_content_type()
            if content_type not in ALLOWED_CONTENT_TYPES:
                return {"error": "unsupported_content_type"}

            html_data = response.read(MAX_RESPONSE_SIZE)
            
            # Check if there's more data (meaning it exceeded limit)
            if response.read(1):
                return {"error": "response_too_large"}

            decoded_html = html_data.decode("utf-8", errors="ignore")
            
            analyzer = WebsiteAnalyzer(url)
            analyzer.feed(decoded_html)
            
            return {
                "has_login_form": analyzer.has_login_form,
                "has_password_field": analyzer.has_password_field,
                "has_hidden_elements": analyzer.has_hidden_elements,
                "suspicious_form_destinations_count": len(analyzer.suspicious_form_destinations),
                "external_iframes_count": len(analyzer.external_iframes),
                "external_scripts_count": len(analyzer.external_scripts),
                "external_links_ratio": len(analyzer.external_links) / analyzer.total_links if analyzer.total_links > 0 else 0,
            }

    except urllib.error.URLError:
        return {"error": "network_or_timeout_error"}
    except Exception:
        return {"error": "analysis_error"}
    finally:
        # Ensure we clear thread-local pinned IPs to prevent leaks or stale cache
        if hasattr(_dns_pinning, 'pinned_ips'):
            _dns_pinning.pinned_ips.clear()
