"""Ground-truth check of the real lab captures in data/ (dataset/README.md).

Run it after capturing with dataset/capture_dataset.sh + attack_runner.sh:

    .venv\\Scripts\\python.exe "tests/phase 5/test_dataset.py"

A PCAP that is missing or still empty (24-byte header only) is skipped.
For every capture the report, the JSON alerts and a summary table are written
to tests/phase 5/results/dataset/ (summary.txt).
"""

import sys
import unittest
from pathlib import Path


TEST_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = TEST_DIR.parents[1]
for directory in ("phase 2", "phase 3", "phase 4", "phase 5"):
    sys.path.insert(0, str(WORKSPACE_ROOT / "ids" / directory))
sys.path.insert(0, str(TEST_DIR))

from ground_truth import GROUND_TRUTH, PCAP_GLOBAL_HEADER_BYTES, expected_sids
from rule_engine import analyze_pcap_to_file
from rule_loader import load_rules


DATA_DIR = WORKSPACE_ROOT / "data"
RESULTS_DIR = TEST_DIR / "results" / "dataset"


class DatasetGroundTruthTests(unittest.TestCase):
    rows: list[str] = []

    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules()
        cls.rows = []

    @classmethod
    def tearDownClass(cls):
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        header = f"{'scenario':18} {'expected':9} {'alerts (sid:count)':28} verdict"
        lines = [header, "-" * len(header), *cls.rows]
        (RESULTS_DIR / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_captures_match_ground_truth(self):
        for scenario, (relative, _sid) in GROUND_TRUTH.items():
            with self.subTest(scenario=scenario):
                self.check(scenario, DATA_DIR / relative)

    def check(self, scenario: str, pcap: Path) -> None:
        expected = expected_sids(scenario)
        expected_text = ",".join(map(str, expected)) or "none"
        if not pcap.is_file() or pcap.stat().st_size <= PCAP_GLOBAL_HEADER_BYTES:
            self.rows.append(f"{scenario:18} {expected_text:9} {'-':28} NOT CAPTURED")
            self.skipTest(f"{pcap.relative_to(DATA_DIR)} has no packets yet")

        relative = pcap.relative_to(DATA_DIR)
        output = RESULTS_DIR / relative.parent / relative.stem
        pipeline = analyze_pcap_to_file(
            pcap,
            output.with_name(f"{relative.stem}_verbose.txt"),
            self.rules,
            alerts_path=output.with_name(f"{relative.stem}_alerts.jsonl"),
            output_mode="verbose",
        )
        counts = pipeline.engine.stats.alerts_by_sid
        found = set(counts)
        missing = expected - found
        unexpected = found - expected
        if not missing and not unexpected:
            verdict = "OK"
        elif missing:
            verdict = f"MISSED {sorted(missing)}" + (f" + FP {sorted(unexpected)}" if unexpected else "")
        else:
            verdict = f"FP {sorted(unexpected)}"
        alert_text = ", ".join(f"{sid}:{count}" for sid, count in sorted(counts.items())) or "none"
        self.rows.append(f"{scenario:18} {expected_text:9} {alert_text:28} {verdict}")

        self.assertFalse(missing, f"{scenario}: expected SID {sorted(missing)} not raised (alerts: {alert_text})")
        self.assertFalse(unexpected, f"{scenario}: unexpected SID {sorted(unexpected)} (alerts: {alert_text})")


if __name__ == "__main__":
    unittest.main()
