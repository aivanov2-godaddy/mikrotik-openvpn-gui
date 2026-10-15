"""Keep the public security-assurance claims scoped to their evidence."""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSURANCE_DOCUMENT = ROOT / "docs" / "SECURITY_ASSURANCE.md"
VALID_MATRIX_STATUSES = {"TESTED", "PARTIAL", "GAP", "N/A", "EXTERNAL"}
SCOPED_ASVS_CONTROLS = frozenset(
    {
        "V3.3.1",
        "V3.3.2",
        "V3.3.3",
        "V3.3.4",
        "V3.3.5",
        "V3.5.1",
        "V7.1.1",
        "V7.1.2",
        "V7.1.3",
        "V7.2.1–V7.2.3",
        "V7.2.4",
        "V7.3.1–V7.3.2",
        "V7.4.1",
        "V7.4.2",
        "V7.4.3",
        "V7.4.4",
        "V7.4.5",
        "V7.5.1",
        "V7.5.2",
        "V7.5.3",
        "V7.6.1",
        "V7.6.2",
        "V8.1.1",
        "V8.1.2",
        "V8.1.3–V8.1.4",
        "V8.2.1",
        "V8.2.2",
        "V8.2.3",
        "V8.2.4",
        "V8.3.1",
        "V8.3.2",
        "V8.3.3",
        "V8.4.1",
        "V8.4.2",
        "V4.4.1",
        "V4.4.2",
        "V4.4.3–V4.4.4",
    }
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
        actual_controls = {row[0] for row in matrix[1:]}
        self.assertEqual(actual_controls, SCOPED_ASVS_CONTROLS)

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

    def test_routeros_credential_memory_tradeoff_is_not_claimed_as_resolved(self) -> None:
        self.assertIn("Risk decision status: unresolved.", self.document)
        self.assertIn("no second password store is introduced", self.document)


if __name__ == "__main__":
    unittest.main()
