from mercury.ai.analyst import analyze_findings


def test_rule_based_analysis_prioritizes_severity(monkeypatch):
    monkeypatch.delenv("MERCURY_AI_BASE_URL", raising=False)
    monkeypatch.delenv("MERCURY_AI_API_KEY", raising=False)
    monkeypatch.delenv("MERCURY_AI_MODEL", raising=False)
    findings = [
        {"severity": "low", "title": "Low"},
        {"severity": "critical", "title": "Critical"},
        {"severity": "medium", "title": "Medium"},
    ]
    result = analyze_findings(findings)
    assert result["mode"] == "rule_based"
    assert [item["title"] for item in result["prioritized_findings"]] == [
        "Critical", "Medium", "Low"
    ]
