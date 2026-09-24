import pytest
import urllib.error
from unittest.mock import patch, MagicMock
from app.services.threat_intel.base import ThreatIntelResult
from app.services.threat_intel.urlhaus import URLhausProvider
from app.services.threat_intel.virustotal import VirusTotalProvider
from app.services.threat_intel import check_url_reputation
from app import create_app


@pytest.fixture
def app():
    app = create_app("testing")
    return app


def test_urlhaus_provider_malicious(app):
    with app.app_context():
        provider = URLhausProvider()
        with patch("app.services.threat_intel.urlhaus.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.getcode.return_value = 200
            mock_resp.read.return_value = b'{"query_status": "ok", "tags": ["malware"]}'
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp
            
            result = provider.check_url("http://evil.com")
            
            assert result is not None
            assert result.is_malicious is True
            assert result.provider_name == "URLhaus"
            assert "malware" in result.tags


def test_urlhaus_provider_not_found(app):
    with app.app_context():
        provider = URLhausProvider()
        with patch("app.services.threat_intel.urlhaus.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.getcode.return_value = 200
            mock_resp.read.return_value = b'{"query_status": "no_results"}'
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp
            
            result = provider.check_url("http://safe.com")
            
            assert result is not None
            assert result.is_malicious is False
            assert result.is_safe is False
            assert result.confidence == 0.5


def test_urlhaus_provider_timeout_graceful(app):
    with app.app_context():
        provider = URLhausProvider()
        with patch("app.services.threat_intel.urlhaus.urllib.request.urlopen", side_effect=urllib.error.URLError("Timeout")):
            result = provider.check_url("http://timeout.com")
            assert result is None


def test_threat_intel_orchestrator(app):
    with app.app_context():
        with patch("app.services.threat_intel.urlhaus.URLhausProvider.check_url") as mock_check:
            mock_result = ThreatIntelResult("URLhaus", True, False, False, 1.0, ["phishing"], {})
            mock_check.return_value = mock_result
            
            results = check_url_reputation("http://test.com")
            assert len(results) == 1
            assert results[0].is_malicious is True


def test_threat_intel_orchestrator_graceful_fail(app):
    with app.app_context():
        with patch("app.services.threat_intel.urlhaus.URLhausProvider.check_url", side_effect=Exception("Crash")), \
             patch("app.services.threat_intel.virustotal.VirusTotalProvider.check_url", side_effect=Exception("Crash")):
            # The orchestrator should swallow the exception and return empty list
            results = check_url_reputation("http://crash.com")
            assert results == []

def test_virustotal_provider_disabled_without_key(app):
    with app.app_context():
        app.config["THREAT_INTEL_VIRUSTOTAL_API_KEY"] = ""
        provider = VirusTotalProvider()
        result = provider.check_url("http://test.com")
        assert result is None

def test_virustotal_provider_malicious(app):
    with app.app_context():
        app.config["THREAT_INTEL_VIRUSTOTAL_API_KEY"] = "mock_key"
        provider = VirusTotalProvider()
        with patch("app.services.threat_intel.virustotal.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.getcode.return_value = 200
            
            mock_data = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 1,
                            "harmless": 80,
                            "undetected": 5
                        }
                    }
                }
            }
            import json
            mock_resp.read.return_value = json.dumps(mock_data).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp
            
            result = provider.check_url("http://evil.com")
            
            assert result is not None
            assert result.is_malicious is True
            assert result.provider_name == "VirusTotal"
            assert result.confidence == round(4 / 89, 2)
            assert "VT_3_engines_malicious" in result.tags

def test_virustotal_provider_404_not_found(app):
    with app.app_context():
        app.config["THREAT_INTEL_VIRUSTOTAL_API_KEY"] = "mock_key"
        provider = VirusTotalProvider()
        with patch("app.services.threat_intel.virustotal.urllib.request.urlopen", side_effect=urllib.error.HTTPError("url", 404, "Not Found", {}, None)):
            result = provider.check_url("http://unknown.com")
            assert result is not None
            assert result.is_malicious is False
            assert result.confidence == 0.5
