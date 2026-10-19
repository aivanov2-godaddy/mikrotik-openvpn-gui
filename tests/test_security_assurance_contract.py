"""Keep the public security-assurance claims scoped to their evidence."""

from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSURANCE_DOCUMENT = ROOT / "docs" / "SECURITY_ASSURANCE.md"
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


if __name__ == "__main__":
    unittest.main()
