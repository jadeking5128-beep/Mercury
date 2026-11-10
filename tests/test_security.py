import pytest

from mercury.engine.scanner import ALLOWED_MODULES, run_assessment
from mercury.security.scope import normalize_hostname


def test_hostname_normalization():
    assert normalize_hostname("HTTPS://Example.COM/path") == "example.com"
    assert normalize_hostname("example.com.") == "example.com"


@pytest.mark.parametrize("value", ["", "http://user:pass@example.com", "127.0.0.1",
                                    "example.com/path", "-bad.example"])
def test_rejects_invalid_targets(value):
    with pytest.raises(ValueError):
        normalize_hostname(value)


def test_scan_rejects_unknown_modules_before_network():
    with pytest.raises(ValueError, match="Unsupported scan modules"):
        run_assessment("example.com", ["arbitrary-command"])


def test_module_allowlist_is_explicit():
    assert ALLOWED_MODULES == {"dns", "http", "tls", "headers", "nmap"}
