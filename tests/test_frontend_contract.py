import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FrontendLiveUpdateContractTests(unittest.TestCase):
    def test_policy_template_apply_requires_the_current_review_receipt(self) -> None:
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("form.dataset.policyReviewToken = payload.review_token || ''", source)
        self.assertIn("form.dataset.policyReviewToken = ''", source)
        self.assertIn("clearTemplatePreview(event.currentTarget)", source)
        self.assertIn("review_token: form.dataset.policyReviewToken || ''", source)
        self.assertIn("catch (error) { clearTemplatePreview(form);", source)

    def test_device_revocation_requires_fresh_routeros_preview_receipt(self) -> None:
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        template = (ROOT / "templates.py").read_text(encoding="utf-8")
        self.assertIn("/revoke/preview", source)
        self.assertIn("review_token: data.get('review_token')", source)
        self.assertIn("form.elements.review_token.value = ''", source)
        self.assertIn("data-revoke-review", source)
        self.assertIn("data-revoke-apply disabled", template)
        self.assertIn("does not disconnect active VPN sessions", template)

    def test_status_updates_only_compare_rendered_user_cards(self) -> None:
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("$('.user-card[data-user-id][data-user-name]')", source)
        self.assertNotIn("const cards = $$('[data-user-id]');", source)

    def test_status_updates_guard_missing_user_metadata(self) -> None:
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("if (!user) return;", source)

    def test_live_rates_use_one_receive_clock_and_ignore_short_intervals(self) -> None:
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("const MIN_RATE_SAMPLE_INTERVAL_MS = 5000;", source)
        self.assertIn("if (previous && timestamp <= previous.timestamp) return;", source)
        self.assertIn("if (previous && timestamp - previous.timestamp < MIN_RATE_SAMPLE_INTERVAL_MS)", source)
        self.assertIn("const timestamp = Date.now();", source)
        self.assertNotIn("Number(payload.generated_at || Math.floor(Date.now() / 1000)) * 1000", source)

    def test_graph_visibility_controls_do_not_pause_live_sample_updates(self) -> None:
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("graphs.dataset.graphView = selected;", source)
        self.assertIn("function updateGraphs(card, rates)", source)
        self.assertIn("document.addEventListener('click', (event) => {", source)
        self.assertIn("data-graph-view", source)

    def test_history_filters_are_local_and_count_visible_rows(self) -> None:
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("function applyHistoryFilters()", source)
        self.assertIn("data-history-category", source)
        self.assertIn("data-history-outcome", source)
        self.assertIn("data-history-from", source)
        self.assertIn("data-history-to", source)
        self.assertIn("${shown} shown · ${rows.length} loaded", source)


if __name__ == "__main__":
    unittest.main()
