import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def css_block(css: str, prelude: str) -> str:
    """Return a CSS block body, ignoring comments and balancing nested braces."""
    source = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    match = re.search(rf"(?m)(?:^|[{{}}])\s*{re.escape(prelude)}\s*\{{", source)
    if not match:
        raise AssertionError(f"CSS block not found: {prelude}")

    opening = source.find("{", match.start())
    depth = 1
    for index in range(opening + 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"Unclosed CSS block: {prelude}")


class AccessibilityRegressionContractTests(unittest.TestCase):
    def test_keyboard_focus_indicator_has_visible_outline_and_offset(self) -> None:
        css = (ROOT / "static" / "app.css").read_text(encoding="utf-8")
        focus = css_block(css, ":focus-visible").lower()
        self.assertRegex(focus, r"\boutline\s*:\s*3px\s+solid\s+#49b9ff\s*;")
        self.assertRegex(focus, r"\boutline-offset\s*:\s*3px\s*;")

    def test_reduced_motion_limits_animation_transition_and_smooth_scroll(self) -> None:
        css = (ROOT / "static" / "app.css").read_text(encoding="utf-8")
        reduced_motion = css_block(css, "@media (prefers-reduced-motion: reduce)")
        override = css_block(reduced_motion, "*, *::before, *::after").lower()
        self.assertRegex(override, r"\bscroll-behavior\s*:\s*auto\s*!important\s*;")
        self.assertRegex(override, r"\banimation-duration\s*:\s*\.0*1ms\s*!important\s*;")
        self.assertRegex(override, r"\banimation-iteration-count\s*:\s*1\s*!important\s*;")
        self.assertRegex(override, r"\btransition-duration\s*:\s*\.0*1ms\s*!important\s*;")

    def test_forced_colors_keeps_keyboard_focus_visible(self) -> None:
        css = (ROOT / "static" / "app.css").read_text(encoding="utf-8")
        forced_colors = css_block(css, "@media (forced-colors: active)")
        focus = css_block(forced_colors, ":focus-visible").lower()
        self.assertRegex(focus, r"\boutline\s*:\s*2px\s+solid\s+canvastext\s*;")
        self.assertRegex(focus, r"\bbox-shadow\s*:\s*none\s*;")
        self.assertRegex(forced_colors.lower(), r"\bborder-color\s*:\s*buttontext\s*;")

    def test_mobile_breakpoints_remain_defined(self) -> None:
        css = (ROOT / "static" / "app.css").read_text(encoding="utf-8")
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
