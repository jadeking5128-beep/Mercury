from mercury.tools.registry import TOOL_SPECS, discover_tools


def test_registry_has_unique_binaries():
    binaries = [spec.binary for spec in TOOL_SPECS]
    assert len(binaries) == len(set(binaries))


def test_discovery_returns_all_registered_tools():
    results = discover_tools()
    assert len(results) == len(TOOL_SPECS)
    assert all(item.name and item.binary for item in results)
    assert all(isinstance(item.installed, bool) for item in results)
