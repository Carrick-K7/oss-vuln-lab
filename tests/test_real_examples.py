import base64
import hashlib
import unittest
from pathlib import Path

from oss_vuln_digger.corpus import CorpusStore
from oss_vuln_digger.impact import load_impact_manifest


ROOT = Path(__file__).resolve().parents[1]


class RealExampleTests(unittest.TestCase):
    def test_zlib_cve_2022_37434_corpus_record_loads(self) -> None:
        record = CorpusStore(str(ROOT / "corpus")).load_record("CVE-2022-37434")

        self.assertEqual(record.project, "zlib")
        self.assertEqual(record.replay.candidate_file, "inflate.c")
        self.assertIn("inflateGetHeader", record.replay.notes)
        self.assertEqual(record.replay.artifacts[0].name, "zlib-cve-2022-37434-payload.gz")
        self.assertEqual(record.replay.artifacts[1].name, "zlib-cve-2022-37434-replay.c")
        payload = base64.b64decode(record.replay.artifacts[0].content)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), record.metadata["payload_sha256"])
        self.assertIn("inflateGetHeader", record.replay.artifacts[1].content)

    def test_zlib_cve_2022_37434_impact_manifest_loads(self) -> None:
        manifest = load_impact_manifest(ROOT / "examples/impact/zlib-cve-2022-37434.json")

        self.assertEqual(manifest.name, "zlib-cve-2022-37434-impact")
        self.assertEqual(manifest.replay.corpus_ref, "CVE-2022-37434")
        self.assertEqual([item.version for item in manifest.version_source.explicit], ["1.2.12", "1.2.13"])
        self.assertEqual({item.classification for item in manifest.source_signatures}, {"vulnerable", "fixed"})
