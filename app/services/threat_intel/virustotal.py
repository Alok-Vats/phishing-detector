"""VirusTotal Threat Intelligence Provider."""

from __future__ import annotations
import base64
import json
import urllib.request
import urllib.error
from flask import current_app
from app.services.threat_intel.base import ThreatIntelProvider, ThreatIntelResult


class VirusTotalProvider(ThreatIntelProvider):
    @property
    def provider_name(self) -> str:
        return "VirusTotal"
        
    def _is_enabled(self) -> bool:
        if not current_app.config.get("THREAT_INTEL_VIRUSTOTAL_ENABLED", True):
            return False
        if not current_app.config.get("THREAT_INTEL_VIRUSTOTAL_API_KEY"):
            return False
        return True
        
    def _get_api_key(self) -> str:
        return current_app.config.get("THREAT_INTEL_VIRUSTOTAL_API_KEY", "")

    def _get_timeout(self) -> int:
        return current_app.config.get("THREAT_INTEL_TIMEOUT_SECONDS", 3)

    def check_url(self, url: str) -> ThreatIntelResult | None:
        if not self._is_enabled():
            return None
            
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            req = urllib.request.Request(api_url, headers={"x-apikey": self._get_api_key()})
            
            with urllib.request.urlopen(req, timeout=self._get_timeout()) as response:
                if response.getcode() != 200:
                    return None
                data = json.loads(response.read().decode("utf-8"))
            
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            
            total_votes = malicious + suspicious + harmless + undetected
            if total_votes == 0:
                # No data yet
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    is_malicious=False,
                    is_suspicious=False,
                    is_safe=False,
                    confidence=0.5,
                    tags=[],
                    raw_response=stats
                )
                
            is_malicious = malicious >= 2  # Considers 2 or more malicious votes as malicious
            is_suspicious = (malicious == 1 or suspicious >= 2) and not is_malicious
            is_safe = harmless > (malicious + suspicious) and malicious == 0
            
            if is_malicious or is_suspicious:
                confidence = min(1.0, (malicious + suspicious) / max(total_votes, 1))
            else:
                confidence = min(1.0, harmless / max(total_votes, 1))

            tags = []
            if is_malicious: tags.append(f"VT_{malicious}_engines_malicious")
            elif is_suspicious: tags.append(f"VT_suspicious")
            
            return ThreatIntelResult(
                provider_name=self.provider_name,
                is_malicious=is_malicious,
                is_suspicious=is_suspicious,
                is_safe=is_safe,
                confidence=round(confidence, 2),
                tags=tags,
                raw_response=stats  # Safe logging, no secret info in stats
            )
            
        except urllib.error.HTTPError as e:
            if e.code == 404: # Not found in VT
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    is_malicious=False,
                    is_suspicious=False,
                    is_safe=False,
                    confidence=0.5,
                    tags=[],
                    raw_response={}
                )
            # 401, 403, 429 etc -> fail gracefully (rate limit or bad key)
            return None
        except Exception:
            return None

    def check_ip(self, ip_address: str) -> ThreatIntelResult | None:
        if not self._is_enabled():
            return None
        try:
            api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            req = urllib.request.Request(api_url, headers={"x-apikey": self._get_api_key()})
            
            with urllib.request.urlopen(req, timeout=self._get_timeout()) as response:
                if response.getcode() != 200:
                    return None
                data = json.loads(response.read().decode("utf-8"))
            
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            is_malicious = malicious >= 2
            
            return ThreatIntelResult(
                provider_name=self.provider_name,
                is_malicious=is_malicious,
                is_suspicious=False,
                is_safe=False,
                confidence=1.0 if is_malicious else 0.5,
                tags=[],
                raw_response=stats
            )
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ThreatIntelResult(
                    provider_name=self.provider_name,
                    is_malicious=False,
                    is_suspicious=False,
                    is_safe=False,
                    confidence=0.5,
                    tags=[],
                    raw_response={}
                )
            return None
        except Exception:
            return None
