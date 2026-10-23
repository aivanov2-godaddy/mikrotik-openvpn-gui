"""Keep the public security-assurance claims scoped to their evidence."""

from __future__ import annotations

import ast
import inspect
import json
import re
import unittest
from pathlib import Path

from app import DashboardHandler


ROOT = Path(__file__).resolve().parents[1]
ASSURANCE_DOCUMENT = ROOT / "docs" / "SECURITY_ASSURANCE.md"
ROUTE_AUTHORIZATION_DOCUMENT = ROOT / "docs" / "ROUTE_AUTHORIZATION.md"
SESSION_LIFETIME_DOCUMENT = ROOT / "docs" / "SESSION_LIFETIME_RATIONALE.md"
ASVS_CONTROL_FIXTURE = ROOT / "tests" / "fixtures" / "asvs_5_0_0_scoped_control_ids.json"
VALID_MATRIX_STATUSES = {"TESTED", "PARTIAL", "GAP", "N/A", "EXTERNAL"}
EXPECTED_ASVS_VERSION = "5.0.0"
EXPECTED_ASVS_SOURCE = "https://github.com/OWASP/ASVS/tree/v5.0.0_release"
EXPECTED_ASVS_SOURCE_ARTIFACT = (
    "https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0_release/5.0/docs_en/"
    "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
)
EXPECTED_ASVS_SOURCE_SHA256 = (
    "bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35"
)
ASVS_CONTROL_ID = re.compile(r"V[1-9]\d*\.[1-9]\d*\.[1-9]\d*")
ASVS_CONTROL_RANGE = re.compile(
    rf"(?P<start>{ASVS_CONTROL_ID.pattern})\s*[-\u2013\u2014]\s*"
    rf"(?P<end>{ASVS_CONTROL_ID.pattern})"
)
TEST_REFERENCE = re.compile(
    r"(tests/[A-Za-z0-9_./]+\.py)::([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
)


def _markdown_cells(row: str) -> list[str]:
    return [cell.strip() for cell in row.strip().strip("|").split("|")]


def _assurance_matrix(document: str) -> list[list[str]]:
    header = "| ASVS 5.0.0 control | Status | Scoped finding and evidence |"
    lines = document.splitlines()
    try:
        header_index = lines.index(header)
    except ValueError as error:
        raise AssertionError("scoped ASVS matrix header is missing or changed") from error

    table: list[list[str]] = []
    for line in lines[header_index:]:
        if not line.startswith("|"):
            break
        cells = _markdown_cells(line)
        if cells and all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        table.append(cells)
    return table


def _load_asvs_control_fixture() -> dict[str, object]:
    fixture = json.loads(ASVS_CONTROL_FIXTURE.read_text(encoding="utf-8"))
    if not isinstance(fixture, dict):
        raise AssertionError("ASVS control fixture must be a JSON object")
    return fixture


def _documented_route_patterns(document: str) -> dict[str, set[str]]:
    """Return method-bound route patterns from the route inventory tables."""
    patterns = {method: set() for method in ("GET", "POST", "PATCH", "DELETE")}
    route_column: int | None = None
    path_pattern = re.compile(
        r"/(?:api|metrics|healthz|readyz|dashboard|login|logout|share)"
        r"(?:/(?:\{[^}]+\}|[^/\s`;|,]+))*|/(?=\s|$)"
    )
    token_pattern = re.compile(
        r"(?P<method>GET|POST|PATCH|DELETE)\b|(?P<path>"
        + path_pattern.pattern
        + r")"
    )

    for line in document.splitlines():
        if line.startswith("| Route |"):
            route_column = 0
            continue
        if line.startswith("| Capability |"):
            route_column = 1
            continue
        if line.startswith("## "):
            route_column = None
            continue
        if route_column is None or not line.startswith("|"):
            continue

        cells = line.split("|")
        if len(cells) <= route_column + 1:
            continue
        current_method: str | None = None
        for span in re.findall(r"`([^`]+)`", cells[route_column + 1]):
            for token in token_pattern.finditer(span):
                if token.group("method"):
                    current_method = token.group("method")
                elif current_method and token.group("path"):
                    patterns[current_method].add(token.group("path").rstrip(".;"))

    return patterns


def _documented_route_regex(route: str) -> str:
    """Translate a route family token into a regex for its documented paths."""
    pieces: list[str] = []
    index = 0
    while index < len(route):
        if route[index] == "{":
            closing = route.find("}", index + 1)
            if closing < 0:
                pieces.append(re.escape(route[index]))
                index += 1
                continue
            options = route[index + 1:closing].split(",")
            if len(options) == 1:
                pieces.append("[^/]+")
            else:
                pieces.append("(?:" + "|".join(re.escape(option) for option in options) + ")")
            index = closing + 1
        elif route[index] == "*":
            pieces.append(".*")
            index += 1
        else:
            pieces.append(re.escape(route[index]))
            index += 1
    return "".join(pieces)


def _representative_dispatch_paths(pattern: str) -> set[str]:
    """Choose valid representative paths for every branch in a dispatch regex."""
    paths = [""]
    index = 0
    for match in re.finditer(r"\(([^()]*)\)", pattern):
        literal = pattern[index:match.start()]
        paths = [path + literal for path in paths]
        group = match.group(1)
        if "|" in group:
            choices = group.split("|")
        elif group == r"[^/]+":
            choices = ["sample"]
        elif group == r"\d+":
            choices = ["1"]
        elif group == r"[A-Za-z0-9_-]{1,64}":
            choices = ["template-1"]
        elif group == r"[A-Za-z0-9_-]{8,96}":
            choices = ["token-12345678"]
        elif group == r"[A-Za-z0-9_-]{32,64}":
            choices = ["s" * 32]
        else:
            raise AssertionError(f"unclassified route regex capture: ({group})")
        paths = [path + choice for path in paths for choice in choices]
        index = match.end()
    suffix = pattern[index:]
    return {path + suffix for path in paths}


def _expand_asvs_control_cell(cell: str) -> list[str]:
    """Expand a single ASVS identifier or an inclusive same-section range."""
    if ASVS_CONTROL_ID.fullmatch(cell):
        return [cell]

    match = ASVS_CONTROL_RANGE.fullmatch(cell)
    if match is None:
        raise ValueError(f"invalid ASVS control or range: {cell!r}")

    start_parts = tuple(int(part) for part in match.group("start")[1:].split("."))
    end_parts = tuple(int(part) for part in match.group("end")[1:].split("."))
    if start_parts[:2] != end_parts[:2]:
        raise ValueError(f"ASVS range must remain within one section: {cell!r}")
    if start_parts[2] > end_parts[2]:
        raise ValueError(f"ASVS range must be in ascending order: {cell!r}")

    chapter, section, first_requirement = start_parts
    last_requirement = end_parts[2]
    return [
        f"V{chapter}.{section}.{requirement}"
        for requirement in range(first_requirement, last_requirement + 1)
    ]


def _has_definition(node: ast.AST, names: list[str]) -> bool:
    if not names:
        return True
    if len(names) == 1:
        # Some evidence references use the module-qualified shorthand for a
        # unittest method; accept it only if that named test exists exactly
        # once somewhere in the module's class/function tree.
        matches = [
            child
            for child in ast.walk(node)
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == names[0]
        ]
        return len(matches) == 1
    body = getattr(node, "body", ())
    for child in body:
        if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if child.name == names[0] and _has_definition(child, names[1:]):
                return True
    return False


class SecurityAssuranceDocumentContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = ASSURANCE_DOCUMENT.read_text(encoding="utf-8")

    def test_scope_and_non_certification_boundary_are_explicit(self) -> None:
        for control in (
            "V3.3.1–V3.3.5 (Cookie Setup)",
            "V3.5.1 (Browser\nOrigin Separation)",
            "ASVS 5.0.0 V7 (Session Management)",
            "V8 (Authorization)",
            "V4.4 (WebSocket)",
        ):
            with self.subTest(control=control):
                self.assertIn(control, self.document)

        self.assertIn("This is not\na security certification, penetration test", self.document)
        self.assertIn("It does not cover the rest of ASVS or establish conformance", self.document)
        self.assertIn("does not assert full ASVS Level 1 or Level 2 conformance", self.document)

    def test_every_control_has_a_valid_status_and_scoped_evidence(self) -> None:
        matrix = _assurance_matrix(self.document)
        self.assertGreater(len(matrix), 1)
        self.assertEqual(
            matrix[0],
            ["ASVS 5.0.0 control", "Status", "Scoped finding and evidence"],
        )

        for row in matrix[1:]:
            with self.subTest(control=row[0] if row else "<empty>"):
                self.assertEqual(len(row), 3)
                self.assertTrue(row[0], "control identifier must be present")
                self.assertIn(row[1], VALID_MATRIX_STATUSES)
                self.assertTrue(row[2], "each matrix status must have scoped evidence")

    def test_session_cookie_assurance_matches_non_authenticating_inventory_reference(self) -> None:
        matrix = {
            row[0]: row
            for row in _assurance_matrix(self.document)[1:]
        }
        cookie_control = matrix["V3.3.4"]
        self.assertEqual(cookie_control[1], "TESTED")
        self.assertIn("cookie bearer is returned only in `Set-Cookie`", cookie_control[2])
        self.assertIn("non-authenticating revocation reference", cookie_control[2])

        endpoint = next(
            line for line in self.document.splitlines()
            if line.startswith("| `GET /api/admin/sessions` |")
        )
        self.assertIn("cookie bearer is never included", endpoint)
        self.assertIn("reference is not accepted as a session cookie", endpoint)

    def test_cookie_and_session_controls_name_their_direct_regressions(self) -> None:
        rows = {row[0]: row for row in _assurance_matrix(self.document)[1:]}
        for control in ("V3.3.1", "V3.3.2", "V3.3.3", "V3.3.5"):
            with self.subTest(control=control):
                self.assertIn(
                    "test_login_session_cookie_has_required_host_security_and_size_properties",
                    rows[control][2],
                )
        self.assertIn("test_admin_session_response_fields_are_capability_gated_at_http_boundary", rows["V3.3.4"][2])
        self.assertIn("test_admin_session_revocation_reference_projection_matches_all_routeros_roles", rows["V3.3.4"][2])
        self.assertIn("test_login_page_uses_same_origin_referrer_policy_for_form_submission", rows["V7.6.2"][2])

    def test_logout_access_is_tested_at_the_rendered_operator_view_boundary(self) -> None:
        rows = {row[0]: row for row in _assurance_matrix(self.document)[1:]}
        self.assertEqual(rows["V7.4.4"][1], "TESTED")
        self.assertIn("shared Sign out stays visible and keyboard reachable on every operator view", rows["V7.4.4"][2])
        self.assertIn("no human usability study is claimed", rows["V7.4.4"][2])

    def test_external_deployment_controls_are_not_claimed_as_verified(self) -> None:
        matrix = _assurance_matrix(self.document)
        findings = {
            control: row[2]
            for row in matrix[1:]
            for control in _expand_asvs_control_cell(row[0])
        }

        self.assertIn("configured is unverified deployment evidence", findings["V8.4.2"])
        self.assertIn("must be verified from deployment evidence", findings["V4.4.1"])
        self.assertIn("Residual-risk decision: OPEN", self.document)

    def test_scoped_asvs_matrix_covers_its_declared_control_set(self) -> None:
        matrix = _assurance_matrix(self.document)
        fixture_controls = _load_asvs_control_fixture()["control_ids"]
        self.assertIsInstance(fixture_controls, list)
        actual_controls = [
            control
            for row in matrix[1:]
            for control in _expand_asvs_control_cell(row[0])
        ]
        self.assertEqual(
            len(actual_controls),
            len(set(actual_controls)),
            "ASVS matrix must not repeat a control, including through overlapping ranges",
        )
        self.assertEqual(set(actual_controls), set(fixture_controls))

    def test_asvs_control_fixture_pins_version_source_and_digest(self) -> None:
        fixture = _load_asvs_control_fixture()
        self.assertEqual(fixture.get("asvs_version"), EXPECTED_ASVS_VERSION)
        self.assertEqual(fixture.get("source_url"), EXPECTED_ASVS_SOURCE)
        self.assertEqual(fixture.get("source_artifact_url"), EXPECTED_ASVS_SOURCE_ARTIFACT)

        source_sha256 = fixture.get("source_sha256")
        self.assertIsInstance(source_sha256, str)
        self.assertRegex(source_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(source_sha256, EXPECTED_ASVS_SOURCE_SHA256)

    def test_asvs_control_fixture_ids_are_unique_and_valid(self) -> None:
        fixture_controls = _load_asvs_control_fixture().get("control_ids")
        self.assertIsInstance(fixture_controls, list)
        self.assertTrue(fixture_controls, "ASVS control fixture must not be empty")
        self.assertTrue(
            all(isinstance(control, str) for control in fixture_controls),
            "ASVS fixture control IDs must all be strings",
        )
        self.assertEqual(
            len(fixture_controls),
            len(set(fixture_controls)),
            "ASVS fixture control IDs must be unique",
        )
        for control in fixture_controls:
            with self.subTest(control=control):
                self.assertRegex(control, rf"^{ASVS_CONTROL_ID.pattern}$")

    def test_asvs_matrix_range_expansion_is_inclusive_and_validated(self) -> None:
        self.assertEqual(
            _expand_asvs_control_cell("V7.2.1–V7.2.3"),
            ["V7.2.1", "V7.2.2", "V7.2.3"],
        )
        self.assertEqual(
            _expand_asvs_control_cell("V4.4.3-V4.4.4"),
            ["V4.4.3", "V4.4.4"],
        )
        self.assertEqual(
            _expand_asvs_control_cell("V8.1.3—V8.1.4"),
            ["V8.1.3", "V8.1.4"],
        )
        for invalid_range in ("V7.2.3–V7.2.1", "V7.2.1–V7.3.2", "V7.2.1–V7.2.x"):
            with self.subTest(control_range=invalid_range):
                with self.assertRaises(ValueError):
                    _expand_asvs_control_cell(invalid_range)

    def test_documented_test_references_resolve_to_existing_test_nodes(self) -> None:
        code_spans = re.findall(r"`([^`]+)`", self.document, flags=re.DOTALL)
        references = {
            match
            for span in code_spans
            for match in TEST_REFERENCE.findall(re.sub(r"\s+", "", span))
        }
        self.assertTrue(references, "assurance document should cite automated test evidence")

        for relative_path, qualified_name in sorted(references):
            with self.subTest(reference=f"{relative_path}::{qualified_name}"):
                test_path = (ROOT / Path(relative_path)).resolve()
                test_root = (ROOT / "tests").resolve()
                self.assertTrue(
                    test_path.is_relative_to(test_root),
                    f"referenced test path escapes tests/: {relative_path}",
                )
                self.assertTrue(test_path.is_file(), f"missing referenced test file: {relative_path}")
                module = ast.parse(test_path.read_text(encoding="utf-8"), filename=relative_path)
                self.assertTrue(
                    _has_definition(module, qualified_name.split(".")),
                    f"missing referenced test node: {relative_path}::{qualified_name}",
                )

    def test_status_definitions_do_not_treat_partial_or_external_as_passes(self) -> None:
        for status in VALID_MATRIX_STATUSES:
            self.assertIn(f"`{status}`", self.document)
        self.assertIn("External and partial results are not passes.", self.document)
        cloudflare_session_row = next(
            row for row in _assurance_matrix(self.document) if row[0] == "V7.1.3"
        )
        self.assertEqual(cloudflare_session_row[1], "EXTERNAL")
        self.assertIn("Cloudflare Access", cloudflare_session_row[2])
        self.assertIn("has not been verified", cloudflare_session_row[2])

    def test_route_document_explicitly_covers_logout_authorization(self) -> None:
        route_document = ROUTE_AUTHORIZATION_DOCUMENT.read_text(encoding="utf-8")
        logout_row = next(
            (line for line in route_document.splitlines() if "`POST /logout`" in line),
            "",
        )
        self.assertTrue(logout_row, "route authorization inventory must document logout")
        for boundary in (
            "non-expired RouterOS-authenticated dashboard session",
            "valid form `csrf` token",
            "duplicate `Origin` fields",
            "same-origin `Referer`",
            "Destroys only the calling dashboard session",
            "does not terminate other sessions",
        ):
            with self.subTest(boundary=boundary):
                self.assertIn(boundary, logout_row)
        self.assertIn("foreign `Origin`", route_document)
        self.assertIn("`Origin: null`", route_document)

    def test_route_document_is_reconciled_to_security_sensitive_dispatch_forms(self) -> None:
        route_document = ROUTE_AUTHORIZATION_DOCUMENT.read_text(encoding="utf-8")
        documented = _documented_route_patterns(route_document)
        dispatch_examples: dict[str, set[str]] = {
            method: set() for method in ("GET", "POST", "PATCH", "DELETE")
        }
        primary_session_paths = {
            "GET": {"/", "/healthz", "/readyz", "/login", "/dashboard"},
            "POST": {"/login", "/logout"},
            "PATCH": set(),
            "DELETE": set(),
        }

        for method in dispatch_examples:
            source = inspect.getsource(getattr(DashboardHandler, f"do_{method}"))
            literal_path_routes = set(re.findall(r'path == "(/[^"]*)"', source))
            all_api_strings = set(re.findall(r'["\'](/api/[^"\']+)', source))
            literal_api_routes = set(re.findall(r'path == "(/api/[^\"]+)"', source))
            api_patterns = set(
                re.findall(r're\.fullmatch\(r"(/api/[^\"]+)"\s*,\s*path\)', source)
            )
            self.assertEqual(
                all_api_strings,
                literal_api_routes | api_patterns,
                f"{method} API dispatch syntax must be classified before route-doc coverage",
            )

            dispatch_examples[method].update(literal_api_routes)
            self.assertTrue(
                primary_session_paths[method].issubset(literal_path_routes),
                f"{method} primary entry paths must remain literal dispatches before route-doc coverage",
            )
            dispatch_examples[method].update(primary_session_paths[method])
            dispatch_examples[method].update(
                re.findall(r'path == "(/metrics)"', source)
            )
            for pattern in api_patterns:
                dispatch_examples[method].update(_representative_dispatch_paths(pattern))
            if method == "GET":
                share_patterns = re.findall(
                    r're\.fullmatch\(r"(/share/[^\"]+)"\s*,\s*path\)', source
                )
                dispatch_examples[method].update(
                    path
                    for pattern in share_patterns
                    for path in _representative_dispatch_paths(pattern)
                )

        for method, examples in dispatch_examples.items():
            for path in examples:
                with self.subTest(method=method, path=path):
                    self.assertTrue(
                        any(
                            re.fullmatch(_documented_route_regex(pattern), path)
                            for pattern in documented[method]
                        ),
                        f"{method} {path} is implemented but absent from the authorization inventory",
                    )

        for method, patterns in documented.items():
            for pattern in patterns:
                with self.subTest(method=method, documented_family=pattern):
                    self.assertTrue(
                        any(
                            re.fullmatch(_documented_route_regex(pattern), path)
                            for path in dispatch_examples[method]
                        ),
                        f"{method} {pattern} is documented but has no current dispatch",
                    )

    def test_partial_asvs_statuses_match_the_bounded_evidence(self) -> None:
        rows = {row[0]: row for row in _assurance_matrix(self.document)[1:]}
        for control in (
            "V7.4.2",
            "V7.4.5",
            "V7.5.2",
            "V8.1.1",
            "V8.1.3–V8.1.4",
            "V4.4.2",
        ):
            with self.subTest(control=control):
                self.assertEqual(rows[control][1], "PARTIAL")

        websocket_origin_finding = rows["V4.4.2"][2]
        self.assertIn("require exactly one Origin", websocket_origin_finding)
        self.assertIn(
            "HTTP polling GET may omit Origin only when exactly one same-origin Referer is present",
            websocket_origin_finding,
        )
        self.assertIn(
            "Deployed proxy behavior and independent full-scope review remain unverified",
            websocket_origin_finding,
        )

        self.assertIn("does not proactively invalidate every session", rows["V7.4.2"][2])
        self.assertIn("There is no operation to terminate all sessions", rows["V7.4.5"][2])
        self.assertIn("There is no terminate-all action", rows["V7.5.2"][2])
        self.assertIn("CI now mechanically reconciles every literal/regex", rows["V8.1.1"][2])
        self.assertIn("does not independently prove every authorization decision is correct", rows["V8.1.1"][2])
        self.assertIn("resolved client IP", rows["V8.1.3–V8.1.4"][2])

    def test_delayed_live_role_revocation_is_reported_as_an_asvs_gap(self) -> None:
        rows = {row[0]: row for row in _assurance_matrix(self.document)[1:]}
        role_change = rows["V8.3.2"]

        self.assertEqual(role_change[1], "GAP")
        self.assertIn("15-second stream-role cache", role_change[2])
        self.assertIn("group's policies", role_change[2])
        self.assertIn("up to 10 minutes later", role_change[2])
        self.assertIn("not verified on the deployed RouterOS 7.24.5", role_change[2])
        self.assertIn("Effective authorization on an already-open stream may therefore remain stale", role_change[2])
        self.assertIn("no immediate RouterOS change notification", role_change[2])
        self.assertIn("would not prevent information leakage", role_change[2])

        self.assertIn("user-record change (applied on the next request)", self.document)
        self.assertIn("policy edit (applied when the REST server renews its API login", self.document)
        self.assertIn("https://manual.mikrotik.com/docs/developer-guides/rest-api/", self.document)

    def test_websocket_origin_review_separates_merged_code_from_followup_evidence(self) -> None:
        self.assertIn(
            "reviewed merged source at `8c3a46df3a7e0e8b0dac9e5ed7a979aa06e855f7`",
            self.document,
        )
        self.assertIn(
            "that merged source still permits a WebSocket handshake with no",
            self.document,
        )
        self.assertIn("this follow-up adds a requirement", self.document)
        self.assertIn("This change is not", self.document)
        self.assertIn("V4.4.2 stays PARTIAL pending deployed proxy", self.document)

    def test_live_report_marks_prior_candidate_gate_results_as_historical(self) -> None:
        report = (ROOT / "docs" / "LIVE_TELEMETRY_ACCEPTANCE_REPORT.md").read_text(
            encoding="utf-8"
        )
        report = " ".join(report.split())
        self.assertIn(
            "historical acceptance record for candidate PR #776", report
        )
        self.assertIn(
            "2026-10-24 its exact immutable ARM64 tag and revision were staged/read back on the isolated canary",
            report,
        )
        self.assertIn(
            "new 30-sample, one-minute-spaced readiness observation has started but is not complete",
            report,
        )
        self.assertIn("canary dashboard remains at its app sign-in form", report)

    def test_documented_contextual_login_limit_matches_runtime_defaults(self) -> None:
        limiter_module = ast.parse((ROOT / "security.py").read_text(encoding="utf-8"))
        limiter_class = next(
            node
            for node in limiter_module.body
            if isinstance(node, ast.ClassDef) and node.name == "LoginRateLimiter"
        )
        initializer = next(
            node
            for node in limiter_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "__init__"
        )
        positional_names = [argument.arg for argument in initializer.args.args]
        defaults = dict(
            zip(positional_names[-len(initializer.args.defaults):], initializer.args.defaults)
        )
        self.assertEqual(ast.literal_eval(defaults["limit"]), 5)
        self.assertEqual(ast.literal_eval(defaults["window_seconds"]), 300)

        context_policy = self.document.split(
            "## Contextual inputs used in application decisions", maxsplit=1
        )[1].split("\n## ", maxsplit=1)[0]
        self.assertIn("resolved client IP", context_policy)
        self.assertIn("rolling 300-second window", context_policy)
        self.assertIn("five attempts", context_policy)
        self.assertIn("HTTP 429", context_policy)
        self.assertIn("RouterOS availability failure", context_policy)
        self.assertIn("browser `Origin`", context_policy)
        self.assertIn("[ROUTE_AUTHORIZATION.md](ROUTE_AUTHORIZATION.md)", context_policy)

    def test_session_lifetime_rationale_distinguishes_nist_guidance_from_product_policy(self) -> None:
        rationale = SESSION_LIFETIME_DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("NIST SP 800-63B Section 5.2", rationale)
        self.assertIn("not assigned a NIST Authentication Assurance Level", rationale)
        self.assertIn("does not claim NIST conformance", rationale)

    def test_live_deployment_and_independent_review_gaps_remain_explicit(self) -> None:
        unverified_heading = "## Explicitly unverified live-router / deployment evidence"
        self.assertIn(unverified_heading, self.document)
        unverified = " ".join(
            self.document.split(unverified_heading, maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        self.assertIn("NOT VERIFIED", unverified)
        self.assertIn("RouterOS user permissions and credential-memory exposure", unverified)
        self.assertIn("external log layers", unverified)
        self.assertIn("Complete an independent, requirement-by-requirement ASVS review", unverified)

    def test_latest_publication_is_not_misrepresented_as_independent_review(self) -> None:
        roadmap = " ".join((ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8").split())
        assurance = " ".join(self.document.split())
        self.assertIn(
            "Two bounded, read-only source reviews against PR #791's commit",
            roadmap,
        )
        self.assertIn("PR #803 is the latest published candidate", roadmap)
        self.assertIn("PR #798 adds evidence-gated originless polling", roadmap)
        self.assertIn("PR #794 added WebSocket Origin and admin-session revocation-reference hardening.", roadmap)
        self.assertIn("The two bounded source reviews described above", self.document)
        self.assertIn("examined PR #791's commit, not the changed source in PR #793.", assurance)
        self.assertIn("publication is not an independent security review", assurance)
        self.assertIn("Latest published mainline security changes — PR #798", assurance)
        self.assertIn("Previously published mainline security changes — PR #794", assurance)

    def test_unverified_section_does_not_deny_historical_canary_observations(self) -> None:
        unverified_heading = "## Explicitly unverified live-router / deployment evidence"
        unverified = " ".join(
            self.document.split(unverified_heading, maxsplit=1)[1]
            .split("\n## ", maxsplit=1)[0]
            .split()
        )
        self.assertIn("limited, point-in-time deployment and readiness observations", unverified)
        self.assertIn("not controlled security or operational acceptance tests", unverified)
        self.assertIn("do not close issue #200", unverified)
        self.assertNotIn("contains no live-router", unverified)

    def test_sampler_documentation_matches_enabled_runtime_wiring(self) -> None:
        supervisor_path = ROOT / "telemetry_supervisor.py"
        supervisor = ast.parse(supervisor_path.read_text(encoding="utf-8"))
        sampler = next(
            node
            for node in supervisor.body
            if isinstance(node, ast.ClassDef) and node.name == "TelemetryInterfaceSampler"
        )
        sampler_docstring = " ".join((ast.get_docstring(sampler) or "").lower().split())
        self.assertIn(
            "telemetryruntime constructs it when binary or auto transport is enabled",
            sampler_docstring,
        )
        self.assertIn("starts its sampling worker with the session supervisor", sampler_docstring)
        self.assertIn(
            "does not establish that a particular deployment enables either mode",
            sampler_docstring,
        )
        self.assertIn("has no routeros mutation methods", sampler_docstring)
        self.assertNotIn("no production wiring", sampler_docstring)

    def test_routeros_credential_memory_tradeoff_is_not_claimed_as_resolved(self) -> None:
        self.assertIn("Risk decision status: unresolved.", self.document)
        self.assertIn("no second password store is introduced", self.document)

    def test_local_release_deployer_credential_risks_are_scoped(self) -> None:
        self.assertIn("ROUTEROS_DEPLOY_USERNAME", self.document)
        self.assertIn("ROUTEROS_DEPLOY_PASSWORD", self.document)
        self.assertIn("host-level environment inspection", self.document)
        self.assertIn("those controls remain unverified", self.document)


if __name__ == "__main__":
    unittest.main()
