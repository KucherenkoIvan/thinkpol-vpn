#!/usr/bin/env python3
"""Tests for board.py's ref validation. Run: python3 tickets/test_board.py"""

import importlib.util
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("board", pathlib.Path(__file__).parent / "board.py")
board = importlib.util.module_from_spec(spec)
spec.loader.exec_module(board)


FIXTURE = {
    "PRD.md": """## Functional requirements
| ID | Requirement | Pri | M |
|---|---|---|---|
| N1 | Overlay addresses | must | M0 |
| R4 | DNS follows the rules | must | M1 |

## Release plan
| | Milestone |
|---|---|
| M0 | Overlay |
""",
    "RESIDUAL-RISKS.md": """# Residual risks
## DNS
| # | Residual |
|---|---|
| RR1 | The CNAME |
## IPv6
| RR10 | No guard |
""",
    "DESIGN.md": """# Design
## Rules
## Open questions
## Open questions
""",
    "docs/design/security.md": """# Security design
## Threat model
````
# not a heading
````
""",
}


class AnchorsTest(unittest.TestCase):
    def test_duplicates_get_the_github_suffix(self):
        self.assertEqual(board.anchors_of("## Rules\n## Rules\n## Rules\n"),
                         {"rules", "rules-1", "rules-2"})

    def test_fenced_code_holds_no_headings(self):
        self.assertEqual(board.anchors_of("```\n# not a heading\n```\n## Real\n"), {"real"})


class CheckRefTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(cls.tmp.name)
        for rel, text in FIXTURE.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        cls.heads = board.ref_targets(root)
        cls.prd = board.requirement_ids(root)
        cls.rr = board.residual_rows(root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_prd_requirement_ids_pass_against_the_table(self):
        self.assertIsNone(board.check_ref("N1", self.heads, self.prd, self.rr))
        self.assertIsNotNone(board.check_ref("Z99", self.heads, self.prd, self.rr))

    def test_milestones_are_not_requirement_ids(self):
        self.assertIsNotNone(board.check_ref("M0", self.heads, self.prd, self.rr))

    def test_rr_rows_pass_against_the_table(self):
        self.assertIsNone(board.check_ref("RR10", self.heads, self.prd, self.rr))
        self.assertIsNotNone(board.check_ref("RR99", self.heads, self.prd, self.rr))

    def test_design_refs_resolve_the_anchor_in_the_named_file(self):
        self.assertIsNone(board.check_ref("DESIGN.md#rules", self.heads, self.prd, self.rr))
        self.assertIsNone(board.check_ref("docs/design/security.md#threat-model", self.heads, self.prd, self.rr))
        self.assertIsNotNone(board.check_ref("docs/design/security.md#rules", self.heads, self.prd, self.rr))

    def test_a_ref_names_an_anchor(self):
        self.assertIsNotNone(board.check_ref("DESIGN", self.heads, self.prd, self.rr))
        self.assertIsNotNone(board.check_ref("docs/design/security.md", self.heads, self.prd, self.rr))

    def test_repeated_headings_suffix_is_valid(self):
        self.assertIsNone(board.check_ref("DESIGN.md#open-questions", self.heads, self.prd, self.rr))
        self.assertIsNone(board.check_ref("DESIGN.md#open-questions-1", self.heads, self.prd, self.rr))
        self.assertIsNotNone(board.check_ref("DESIGN.md#open-questions-2", self.heads, self.prd, self.rr))

    def test_residual_file_anchors(self):
        self.assertIsNone(board.check_ref("RESIDUAL-RISKS.md#dns", self.heads, self.prd, self.rr))


if __name__ == "__main__":
    unittest.main()