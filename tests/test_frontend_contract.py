import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FrontendLiveUpdateContractTests(unittest.TestCase):
    def test_status_updates_only_compare_rendered_user_cards(self) -> None:
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("$('.user-card[data-user-id][data-user-name]')", source)
        self.assertNotIn("const cards = $$('[data-user-id]');", source)

    def test_status_updates_guard_missing_user_metadata(self) -> None:
        source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("if (!user) return;", source)


if __name__ == "__main__":
    unittest.main()
