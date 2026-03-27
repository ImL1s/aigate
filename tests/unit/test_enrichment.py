"""Tests for enrichment module integration."""

from aigate.enrichment import EnrichmentResult, KnownVuln, SecurityMention


class TestEnrichmentResult:
    def test_to_prompt_section_empty(self):
        """No sources queried → empty string."""
        r = EnrichmentResult()
        section = r.to_prompt_section()
        assert section == ""

    def test_to_prompt_section_with_docs(self):
        r = EnrichmentResult(
            library_description="HTTP library for Python",
            expected_capabilities=["http requests", "session management"],
            sources_queried=["context7"],
        )
        section = r.to_prompt_section()
        assert "HTTP library" in section
        assert "http requests" in section

    def test_to_prompt_section_with_threat(self):
        r = EnrichmentResult(
            known_vulnerabilities=[
                KnownVuln(id="CVE-2024-1234", summary="RCE in setup.py", severity="CRITICAL"),
            ],
            sources_queried=["osv"],
        )
        section = r.to_prompt_section()
        assert "CVE-2024-1234" in section
        assert "CRITICAL" in section

    def test_to_prompt_section_with_search(self):
        r = EnrichmentResult(
            security_mentions=[
                SecurityMention(
                    title="Users report malicious behavior",
                    url="https://reddit.com/r/test",
                    snippet="malicious code found in v2.0",
                    source="reddit",
                ),
            ],
            sources_queried=["web_search"],
        )
        section = r.to_prompt_section()
        assert "malicious" in section
        assert "reddit" in section

    def test_to_prompt_section_no_vulns_found(self):
        """When OSV was queried but found nothing, should say so."""
        r = EnrichmentResult(sources_queried=["osv"])
        section = r.to_prompt_section()
        assert "No known vulnerabilities" in section

    def test_to_prompt_section_no_search_hits(self):
        """When web search was queried but found nothing, should say so."""
        r = EnrichmentResult(sources_queried=["web_search"])
        section = r.to_prompt_section()
        assert "No recent security reports" in section

    def test_doc_snippets_limited(self):
        """Should only include first 3 doc snippets."""
        r = EnrichmentResult(
            doc_snippets=["a", "b", "c", "d", "e"],
            library_description="test lib",
            sources_queried=["context7"],
        )
        section = r.to_prompt_section()
        assert "- d" not in section
        assert "- e" not in section

    def test_author_info_included(self):
        r = EnrichmentResult(
            author_info="Maintained by Test Corp since 2020",
            sources_queried=["web_search"],
        )
        section = r.to_prompt_section()
        assert "Test Corp" in section
