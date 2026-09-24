import pytest
from unittest.mock import patch, MagicMock
import urllib.error
import socket
from app.services.website_analysis import fetch_and_analyze, get_and_validate_ip

def mock_getaddrinfo(host, port, *args, **kwargs):
    if host == "github.com":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', port))]
    if host == "localhost":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port))]
    if host == "169.254.169.254":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', port))]
    if host == "192.168.1.5":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.5', port))]
    if host == "10.0.0.1":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', port))]
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (host, port))]

@patch("app.services.website_analysis._original_getaddrinfo", side_effect=mock_getaddrinfo)
def test_get_and_validate_ip(mock_dns):
    # Public IPs
    assert get_and_validate_ip("8.8.8.8") == "8.8.8.8"
    assert get_and_validate_ip("github.com") == "8.8.8.8"
    
    # Private / Loopback IPs
    assert get_and_validate_ip("127.0.0.1") is None
    assert get_and_validate_ip("localhost") is None
    assert get_and_validate_ip("192.168.1.5") is None
    assert get_and_validate_ip("10.0.0.1") is None
    assert get_and_validate_ip("169.254.169.254") is None # AWS metadata

@patch("app.services.website_analysis.get_and_validate_ip")
def test_ssrf_protection_blocked(mock_safe):
    mock_safe.return_value = None
    result = fetch_and_analyze("http://169.254.169.254/latest/meta-data/")
    assert result == {"error": "ssrf_protection_blocked_internal_ip"}

@patch("app.services.website_analysis.get_and_validate_ip")
@patch("urllib.request.urlopen")
def test_normal_html_analysis(mock_urlopen, mock_safe):
    mock_safe.return_value = "8.8.8.8"
    
    mock_resp = MagicMock()
    mock_resp.headers.get_content_type.return_value = "text/html"
    
    html_content = b"""
    <html>
        <body>
            <form action="http://evil.com/login">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="hidden" name="token" value="123">
            </form>
            <iframe src="http://ads.com/frame"></iframe>
            <a href="http://external.com">Link</a>
            <a href="/internal">Link 2</a>
        </body>
    </html>
    """
    mock_resp.read.side_effect = [html_content, b""] 
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    
    result = fetch_and_analyze("http://safe.com")
    
    assert result["has_login_form"] is True
    assert result["has_password_field"] is True
    assert result["has_hidden_elements"] is True
    assert result["suspicious_form_destinations_count"] == 1
    assert result["external_iframes_count"] == 1
    assert result["external_links_ratio"] == 0.5

@patch("app.services.website_analysis.get_and_validate_ip")
@patch("urllib.request.urlopen")
def test_network_failure(mock_urlopen, mock_safe):
    mock_safe.return_value = "8.8.8.8"
    mock_urlopen.side_effect = urllib.error.URLError("Network unreachable")
    
    result = fetch_and_analyze("http://safe.com")
    assert result == {"error": "network_or_timeout_error"}

@patch("app.services.website_analysis.get_and_validate_ip")
@patch("urllib.request.urlopen")
def test_oversized_content(mock_urlopen, mock_safe):
    mock_safe.return_value = "8.8.8.8"
    
    mock_resp = MagicMock()
    mock_resp.headers.get_content_type.return_value = "text/html"
    mock_resp.read.side_effect = [b"a" * (2 * 1024 * 1024), b"b"]
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    
    result = fetch_and_analyze("http://safe.com")
    assert result == {"error": "response_too_large"}
