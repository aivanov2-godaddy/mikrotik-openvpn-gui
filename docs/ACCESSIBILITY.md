# Accessibility

The dashboard keeps the responsive layout usable with keyboard, high-contrast,
and reduced-motion settings:

- Every keyboard-focusable control uses a high-contrast `:focus-visible` ring.
- Windows High Contrast/forced-colors mode receives system-colored outlines and
  borders instead of relying on the dashboard palette.
- `prefers-reduced-motion: reduce` disables smooth scrolling and reduces CSS
  transitions/animations to an effectively static state.
- These preferences are CSS-only and do not change RouterOS configuration,
  stored dashboard data, or deployment behavior.

When reviewing UI changes, test keyboard-only navigation (Tab, Shift+Tab,
Enter, and Escape), a browser zoom of 200%, and both reduced-motion and
forced-colors modes. The responsive breakpoints remain unchanged.
