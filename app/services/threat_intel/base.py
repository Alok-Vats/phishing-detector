"""Base classes and models for the Threat Intelligence layer."""

from __future__ import annotations
import abc
import datetime
from dataclasses import dataclass

@dataclass
class ThreatIntelResult:
    """Normalized response from any threat intelligence provider."""
    provider_name: str
    is_malicious: bool
    is_suspicious: bool
    is_safe: bool
    confidence: float  # 0.0 to 1.0
    tags: list[str]
    raw_response: dict
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now(datetime.UTC).isoformat()

class ThreatIntelProvider(abc.ABC):
    """Abstract base class for all reputation providers."""
    
    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Name of the provider (e.g., 'VirusTotal', 'URLhaus')."""
        pass
    
    @abc.abstractmethod
    def check_url(self, url: str) -> ThreatIntelResult | None:
        """Check a URL against the provider. Returns None if provider fails or times out."""
        pass
        
    @abc.abstractmethod
    def check_ip(self, ip_address: str) -> ThreatIntelResult | None:
        """Check an IP address against the provider."""
        pass
