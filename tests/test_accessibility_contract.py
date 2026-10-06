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

    def test_primary_theme_palettes_define_shared_design_tokens(self) -> None:
        css = (ROOT / "static" / "app.css").read_text(encoding="utf-8")
        tokens = (
            "--workspace",
            "--panel",
            "--panel-2",
            "--text",
            "--text-bright",
            "--muted",
            "--blue",
            "--green",
            "--amber",
            "--red",
        )
        for palette in (":root", 'html[data-theme="dark"]', 'html[data-theme-resolved="light"]'):
            with self.subTest(palette=palette):
                declarations = css_block(css, palette)
                for token in tokens:
                    self.assertRegex(declarations, rf"(?m)^\s*{re.escape(token)}\s*:")
        self.assertRegex(css_block(css, ":root"), r"(?m)^\s*--font\s*:")

    def test_shared_primary_view_roles_use_semantic_tokens(self) -> None:
        css = (ROOT / "static" / "app.css").read_text(encoding="utf-8")
        expected = (
            ("body", "color", "--text"),
            ("body", "background", "--workspace"),
            (".view-heading h1", "color", "--text-bright"),
            (".view-heading p:not(.eyebrow)", "color", "--muted"),
            (".panel-heading strong", "color", "--text-bright"),
            (".metric strong", "color", "--text-bright"),
        )
        for selector, property_name, token in expected:
            with self.subTest(selector=selector, property=property_name):
                declarations = css_block(css, selector).lower()
                self.assertRegex(
                    declarations,
                    rf"\b{re.escape(property_name)}\s*:\s*var\({re.escape(token)}\)\s*;",
                )
        body = css_block(css, "body").lower()
        self.assertRegex(body, r"\bfont\s*:[^;]*var\(--font\)")

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
            "Primary-view design system",
            "Dashboard",
            "VPN Users",
            "Connections",
        ):
            self.assertIn(expected, guide)


if __name__ == "__main__":
    unittest.main()
