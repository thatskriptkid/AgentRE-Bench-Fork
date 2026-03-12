"""Tests for scorer.py: file_type, technique normalization, and standard scoring."""
import sys
import unittest
from pathlib import Path

# Ensure project root is on path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scorer import (
    score_file_type,
    score_set_overlap,
    normalize_technique_set,
    score_standard,
)


class TestScoreFileType(unittest.TestCase):
    """PE32/PE32+ equivalence and long agent descriptions."""

    def test_pe32_pe32_plus_match(self):
        self.assertEqual(score_file_type("PE32+", "PE32"), 1.0)
        self.assertEqual(score_file_type("PE32+", "PE32+"), 1.0)

    def test_long_description_contains_pe32_plus(self):
        agent_val = "PE32+ executable (console) x86-64, for MS Windows"
        self.assertEqual(score_file_type("PE32+", agent_val), 1.0)

    def test_elf_no_match_pe(self):
        self.assertEqual(score_file_type("PE32+", "ELF64"), 0.0)

    def test_none_both(self):
        self.assertEqual(score_file_type(None, None), 1.0)


class TestTechniqueNormalizationAndOverlap(unittest.TestCase):
    """Synonyms (e.g. CreateProcess -> CreateProcess_shell) and Jaccard."""

    def test_createprocess_maps_to_createprocess_shell(self):
        gt = ["CreateProcess_shell", "socket_connect"]
        agent = ["CreateProcess", "socket_connect"]
        gt_n = normalize_technique_set(gt)
        ag_n = normalize_technique_set(agent)
        self.assertEqual(gt_n, ag_n)
        credit, extra = score_set_overlap(gt_n, ag_n)
        self.assertEqual(credit, 1.0)
        self.assertEqual(extra, 0)

    def test_level9_loadlibrary_getprocaddress_dll_loading(self):
        gt = ["LoadLibrary", "GetProcAddress", "dynamic_loading"]
        agent = ["LoadLibraryA", "GetProcAddress", "DLL loading"]
        gt_n = normalize_technique_set(gt)
        ag_n = normalize_technique_set(agent)
        credit, extra = score_set_overlap(gt_n, ag_n)
        self.assertEqual(credit, 1.0)
        self.assertEqual(extra, 0)


class TestScoreStandard(unittest.TestCase):
    """Full standard scoring with fixed ground truth and agent answer."""

    def test_level1_partial_techniques(self):
        gt = {
            "sample": "level1_TCPServer",
            "file_type": "ELF64",
            "encoded_strings": False,
            "decoded_c2": "192.168.1.100:4444",
            "c2_protocol": "TCP",
            "techniques": ["socket_connect", "dup2_redirect", "execve_shell"],
        }
        agent = {
            "file_type": "ELF64",
            "encoded_strings": False,
            "decoded_c2": "192.168.1.100:4444",
            "c2_protocol": "TCP",
            "techniques": ["socket_connect"],
        }
        result = score_standard(gt, agent)
        self.assertEqual(result["tier"], "standard")
        self.assertEqual(result["field_scores"]["decoded_c2"], 1.0)
        self.assertEqual(result["field_scores"]["file_type"], 1.0)
        self.assertLess(result["field_scores"]["techniques"], 1.0)
        self.assertTrue(
            "dup2_redirect" in result["missing_techniques"]
            or "execve_shell" in result["missing_techniques"]
        )
        self.assertGreater(result["final_score"], 0)
        self.assertLessEqual(result["final_score"], 1.0)


if __name__ == "__main__":
    unittest.main()
