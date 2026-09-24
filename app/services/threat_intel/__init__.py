"""Orchestrator for the Threat Intelligence layer."""

from __future__ import annotations
import concurrent.futures
from app.services.threat_intel.base import ThreatIntelResult
from app.services.threat_intel.urlhaus import URLhausProvider
from app.services.threat_intel.virustotal import VirusTotalProvider

def check_url_reputation(url: str) -> list[ThreatIntelResult]:
    """Query all enabled reputation providers concurrently."""
    providers = [URLhausProvider(), VirusTotalProvider()]
    results = []
    
    # Run requests concurrently to respect the low latency requirements
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(providers)) as executor:
        future_to_provider = {
            executor.submit(p.check_url, url): p for p in providers
        }
        for future in concurrent.futures.as_completed(future_to_provider):
            try:
                res = future.result()
                if res:
                    results.append(res)
            except Exception:
                # If a provider crashes entirely, swallow it and continue
                pass
                
    return results
