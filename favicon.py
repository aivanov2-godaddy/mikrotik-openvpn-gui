from __future__ import annotations

import base64


# The compact MikroTik symbol is kept as vector artwork for modern browsers.
FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
<rect width="32" height="32" rx="4" fill="#1b262f"/>
<g fill="none" stroke="#f5f9fc" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.7">
<path d="M16 3 27 9v12L16 28 5 21V9l11-6Z"/>
<path d="m5 9 11 6 11-6M16 15v13M10.7 5.7 21.3 11.9v6.2"/>
</g>
</svg>"""

# A 32x32 PNG-backed ICO fallback. It uses the same mark and dark WinBox
# background, so legacy browsers and pinned shortcuts render consistently.
FAVICON_ICO_B64 = (
    "AAABAAEAICAAAAEAIADWAQAAFgAAAIlQTkcNChoKAAAADUlIRFIAAAAgAAAAIAgGAAAAc3p69AAAAZ1JREFUeNpjkFbT/z+QmIESzc6+oWBMdweALN135MT/rz//gDGITa5DSHKAmYPH/8Ur18MtRscgOZAaqjtAw9gaq8VnLl4FY3Txjv6pYD1UcQDIsOev36NYAOLnlFbD1YDYN+89wlAD0ku2A7AZSii4sTkWZAayYwk6IDAqCWewIic8XL4EBT1IDFt0gczG6wBQSibk0/j0fIyQAfHRDceVYNFzCwO674lN2diCGxRCMLW4HIDuUIIOwJeyQZZs2L4bq6NxmUO0A6bOWUR0ysaVbmDRAzKLZAfAFBKTsgllQ2zmEu0AQikbl89B6YGQuUQ7gJSimKYOIKYyoosD8KkddQAsx4Cy3oA4AJQWqpo6UAotshwAKuHw1enEOhZkBnJpidcB6JURer1PqgNAetELMbyVEcxg9FINuZIhxgEgtehVN7YaE2eDBBRsyOU3tnoAlwOwFd0gs3BFJwOh1i96UQvig8TRHYBPLcWNUlx1PzY2Ke1Bkprl2OIVVyVEStOc5I4JtpRNKMdQvWeEnrcJlRnDr284aHrH1HAAAAMz076VdCvLAAAAAElFTkSuQmCC"
)


def ico_bytes() -> bytes:
    return base64.b64decode(FAVICON_ICO_B64)
