"""Regression tests for consecutive visible programming-step numbering."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "gui"
for entry in (str(GUI), str(ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from utils.pipeline_spec import PIPELINE_STEPS, visible_pipeline_labels  # noqa: E402


class ProgrammingPipelineNumberingTests(unittest.TestCase):
    def test_full_flow_keeps_one_through_ten(self):
        labels = [
            label
            for _sid, label in visible_pipeline_labels("programming")
        ]
        self.assertEqual(
            [label.split(".", 1)[0] for label in labels],
            [str(number) for number in range(1, 11)],
        )
        self.assertEqual(len(labels), len(PIPELINE_STEPS["programming"]))

    def test_hidden_puf_steps_produce_consecutive_visible_numbers(self):
        hidden = {"puf_activate", "program_helper_image", "provision_rkh"}
        visible_steps = {
            sid for sid, _ in PIPELINE_STEPS["programming"]
            if sid not in hidden
        }

        visible_labels = [
            label for _sid, label in visible_pipeline_labels(
                "programming", visible_steps
            )
        ]
        self.assertEqual(
            visible_labels,
            [
                "1. Generate JIC",
                "2. Program Helper Image",
                "3. Program Root Key Hash",
                "4. Program JIC",
                "5. BKP Prefetch",
                "6. BKP Set Authority",
                "7. BKP Provision",
            ],
        )

    def test_hidden_set_authority_is_also_removed_from_numbering(self):
        hidden = {
            "puf_activate",
            "program_helper_image",
            "provision_rkh",
            "set_authority",
        }
        visible_steps = {
            sid for sid, _ in PIPELINE_STEPS["programming"]
            if sid not in hidden
        }
        labels = dict(visible_pipeline_labels("programming", visible_steps))
        self.assertEqual(labels["provision"], "6. BKP Provision")


if __name__ == "__main__":
    unittest.main()
