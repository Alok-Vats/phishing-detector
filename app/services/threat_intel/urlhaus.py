"""URLhaus Threat Intelligence Provider."""

from __future__ import annotations
import urllib.request
import urllib.parse
import urllib.error
import json
from flask import current_app
from app.services.threat_intel.base import ThreatIntelProvider, ThreatIntelResult


class URLhausProvider(ThreatIntelProvider):
    @property
    def provider_name(self) -> str:
        return "URLhaus"
        
    def _is_enabled(self) -> bool:
        return current_app.config.get("THREAT_INTEL_URLHAUS_ENABLED", True)
        
    def _get_timeout(self) -> int:
        return current_app.config.get("THREAT_INTEL_TIMEOUT_SECONDS", 3)
        
    def check_url(self, url: str) -> ThreatIntelResult | None:
        if not self._is_enabled():
            return None
            
        try:
            data = urllib.parse.urlencode({"url": url}).encode("utf-8")
            req = urllib.request.Request(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            with urllib.request.urlopen(req, timeout=self._get_timeout()) as response:
                if response.getcode() != 200:
                    return None
                response_data = json.loads(response.read().decode("utf-8"))
            
            status = response_data.get("query_status", "")
            
            if status == "ok":
                # URL is in URLhaus (malicious)
                tags = response_data.get("tags", []) or []
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    is_malicious=True,
                    is_suspicious=False,
                    is_safe=False,
                    confidence=1.0,
                    tags=tags,
                    raw_response=response_data
                )
            elif status == "no_results":
                # Not found (could be safe or unknown)
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    is_malicious=False,
                    is_suspicious=False,
                    is_safe=False,
                    confidence=0.5,
                    tags=[],
                    raw_response=response_data
                )
            return None
            
        except (urllib.error.URLError, ValueError, Exception):
            # Fail gracefully on network errors, timeouts, or bad JSON
            return None

    def check_ip(self, ip_address: str) -> ThreatIntelResult | None:
        if not self._is_enabled():
            return None
            
        try:
            data = urllib.parse.urlencode({"host": ip_address}).encode("utf-8")
            req = urllib.request.Request(
                "https://urlhaus-api.abuse.ch/v1/payload/",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            with urllib.request.urlopen(req, timeout=self._get_timeout()) as response:
                if response.getcode() != 200:
                    return None
                response_data = json.loads(response.read().decode("utf-8"))
                
            if response_data.get("query_status") == "ok":
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    is_malicious=True,
                    is_suspicious=False,
                    is_safe=False,
                    confidence=1.0,
                    tags=[],
                    raw_response=response_data
                )
            return None
        except Exception:
            return None
