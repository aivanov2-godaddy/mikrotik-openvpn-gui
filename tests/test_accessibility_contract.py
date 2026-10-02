import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AccessibilityRegressionContractTests(unittest.TestCase):
    def test_css_keeps_keyboard_motion_and_forced_color_support(self) -> None:
        css = (ROOT / "static" / "app.css").read_text(encoding="utf-8")
        self.assertIn(":focus-visible", css)
        self.assertIn("@media (prefers-reduced-motion: reduce)", css)
        self.assertIn("@media (forced-colors: active)", css)
        self.assertIn("outline: 2px solid CanvasText", css)
        self.assertIn("@media (max-width: 760px)", css)
        self.assertIn("@media (max-width: 520px)", css)

    def test_accessibility_review_covers_real_operator_views_and_tasks(self) -> None:
        guide = (ROOT / "docs" / "ACCESSIBILITY.md").read_text(encoding="utf-8")
        for expected in (
            "WCAG 2.2 AA",
            "Dashboard",
            "VPN Users",
            "Connections",
            "200% browser",
            "reduced motion",
            "forced",
            "Five operator usability tasks",
            "without moderator hints",
        ):
            self.assertIn(expected, guide)


if __name__ == "__main__":
    unittest.main()
