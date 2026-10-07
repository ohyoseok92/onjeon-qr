from onjeon import analyzer
import ssl


def test_unsigned_url_never_becomes_trusted(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address: (200, None))
    result = analyzer.analyze_url("https://city.example.org/notice", ["city.example.org"])
    assert result["status"] == "warning"
    assert "official_domain_unverified" in result["signals"]
    assert "destination" not in result


def test_unsigned_url_redirect_and_install_signals(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host: "93.184.215.14")
    seen = []

    def head(url, host, address):
        seen.append(host)
        return (302, "https://other.example.net/app.apk") if len(seen) == 1 else (200, None)

    monkeypatch.setattr(analyzer, "_head", head)
    result = analyzer.analyze_url("https://city.example.org/start", ["city.example.org"])
    assert result["status"] == "warning"
    assert result["redirects"] == 1
    assert "left_official_domain" in result["signals"]
    assert "install_file" in result["signals"]
    assert seen == ["city.example.org", "other.example.net"]


def test_private_address_and_downgrade_are_blocked(monkeypatch):
    monkeypatch.setattr(analyzer.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))])
    assert analyzer.analyze_url("https://foo.example.org/", [])["reason"] == "non_public_address"
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address: (302, "http://foo.example.org/"))
    assert analyzer.analyze_url("https://foo.example.org/", [])["reason"] == "unsafe_redirect"


def test_unsupported_url_does_not_trigger_network(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host: (_ for _ in ()).throw(AssertionError("called")))
    for url in ("file:///etc/passwd", "https://127.0.0.1/", "https://user@example.org/", "https://example.org\\@evil.org/"):
        assert analyzer.analyze_url(url, [])["status"] == "blocked"


def test_redirect_limit_is_a_warning(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host: "93.184.215.14")

    def head(url, host, address):
        number = int(url.rsplit("/", 1)[-1])
        return 302, f"https://foo.example.org/{number + 1}"

    monkeypatch.setattr(analyzer, "_head", head)
    result = analyzer.analyze_url("https://foo.example.org/0", [])
    assert result["status"] == "warning"
    assert result["reason"] == "redirect_limit"


def test_ipv4_is_preferred_after_all_addresses_are_checked(monkeypatch):
    monkeypatch.setattr(
        analyzer.socket, "getaddrinfo",
        lambda *args, **kwargs: [(10, 1, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443)), (2, 1, 6, "", ("93.184.215.14", 443))],
    )
    assert analyzer._resolve_public("example.org") == "93.184.215.14"


def test_unicode_path_is_percent_encoded(monkeypatch):
    paths = []

    class FakeResponse:
        status = 200

        def getheader(self, key):
            return None

    class FakeConnection:
        sock = None

        def __init__(self, host, address):
            pass

        def connect(self):
            pass

        def request(self, method, path, headers):
            paths.append(path)

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(analyzer, "_PinnedHTTPSConnection", FakeConnection)
    assert analyzer._head("https://example.org/공지", "example.org", "93.184.215.14") == (200, None)
    assert paths == ["/%EA%B3%B5%EC%A7%80"]


def test_bad_certificate_is_blocked(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address: (_ for _ in ()).throw(ssl.SSLCertVerificationError("bad cert")))
    assert analyzer.analyze_url("https://example.org/", [])["reason"] == "tls_invalid"


def test_full_analyzer_returns_busy_without_network(monkeypatch):
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host: (_ for _ in ()).throw(AssertionError("network called")))
    for _ in range(4):
        analyzer.ANALYSIS_SLOTS.acquire()
    try:
        assert analyzer.analyze_url("https://example.org/", [])["reason"] == "analyzer_busy"
    finally:
        for _ in range(4):
            analyzer.ANALYSIS_SLOTS.release()
