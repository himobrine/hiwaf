"""`export_events_feedback.py` 的纯函数回归：标签口径 / 形态分类 / 去工具特征。"""
from __future__ import annotations

import random
import unittest

import export_events_feedback as ex


class VerdictSideTest(unittest.TestCase):
    def test_human_verdicts_map(self):
        self.assertEqual(ex.VERDICT_SIDE["confirmed_attack"], "attack")
        self.assertEqual(ex.VERDICT_SIDE["missed"], "attack")
        self.assertEqual(ex.VERDICT_SIDE["false_positive"], "benign")
        self.assertEqual(ex.VERDICT_SIDE["confirmed_benign"], "benign")
        # 待查 / 未知都不导出
        self.assertNotIn("uncertain", ex.VERDICT_SIDE)


class ClassifyTest(unittest.TestCase):
    def test_payload_signatures(self):
        self.assertEqual(ex.classify_payload("../../etc/passwd"), 4)
        self.assertEqual(ex.classify_payload("%2e%2e%2fetc%2fpasswd"), 4)
        self.assertEqual(ex.classify_payload(";cat /etc/passwd"), 3)
        self.assertEqual(ex.classify_payload("1 | whoami"), 3)
        self.assertEqual(ex.classify_payload("<script>alert(1)</script>"), 2)
        self.assertEqual(ex.classify_payload("1 AND 1=1"), 1)
        # path-info 型 SQLi 不应被当成 cmdi
        self.assertEqual(ex.classify_payload(";id=1 AND 1=1"), 1)


class DecodeTest(unittest.TestCase):
    def test_multi_decode(self):
        self.assertEqual(ex.decode_payload("id=1%20AND%201=1"), "id=1 AND 1=1")
        # 双重编码只解一层仍需再解
        self.assertEqual(ex.decode_payload("1%2527%2520OR"), "1' OR")
        self.assertEqual(ex.decode_payload("1%27%20OR"), "1' OR")


class VariantsTest(unittest.TestCase):
    def test_attack_gets_three_variants(self):
        rng = random.Random(1)
        out = ex.variants("GET", "/item", "id=1%20AND%201=1", "", 1, rng)
        kinds = [v[-1] for v in out]
        self.assertEqual(kinds, ["orig", "decoded", "reencoded"])
        # 解码变体里不能残留 %27/%20 这类编码指纹
        decoded = [v for v in out if v[-1] == "decoded"][0]
        self.assertIn("1 AND 1=1", ex.decode_payload(decoded[2]))
        self.assertNotIn("%20", decoded[2])
        # 重编码变体必须是百分号编码
        reenc = [v for v in out if v[-1] == "reencoded"][0]
        self.assertIn("%20", reenc[2])

    def test_benign_not_augmented(self):
        rng = random.Random(1)
        out = ex.variants("GET", "/api/items", "id=1&page=2", "", 0, rng)
        self.assertEqual([v[-1] for v in out], ["orig"])

    def test_no_augment_flag(self):
        rng = random.Random(1)
        out = ex.variants("GET", "/x", "id=1%20OR%201=1", "", 1, rng, augment=False)
        self.assertEqual([v[-1] for v in out], ["orig"])


class RebuildQueryTest(unittest.TestCase):
    def test_keeps_other_params(self):
        rng = random.Random(3)
        q = ex.rebuild_query("id=1&Submit=Submit", "1 AND 1=1", encode=False, rng=rng)
        self.assertIn("Submit=Submit", q)
        self.assertIn("1 AND 1=1", ex.decode_payload(q))

    def test_encode_variant_is_encoded(self):
        rng = random.Random(3)
        q = ex.rebuild_query("id=1", "1' OR 1=1--", encode=True, rng=rng)
        self.assertIn("%27", q)


class VisibleEvidenceTest(unittest.TestCase):
    def test_header_only_attack_is_not_a_training_row(self):
        # 裸页面 + Cookie 里的 payload：模型可见字段没有任何攻击特征
        self.assertFalse(ex.has_attack_signal("/sql/sql/Less-3/"))
        self.assertFalse(ex.has_attack_signal("/sql/sql/Less-3/  "))
        # 真正的 path-info / query 注入必须能识别
        self.assertTrue(ex.has_attack_signal("/sql/sql/Less-3/;id=1 AND 1=1"))
        self.assertTrue(ex.has_attack_signal("id=1%20AND%201=1"))

    def test_path_payload_gets_path_variants(self):
        rng = random.Random(1)
        out = ex.variants("GET", "/x/;id=1%20AND%201=1", "", "", 1, rng)
        kinds = [v[-1] for v in out]
        self.assertIn("path-decoded", kinds)


if __name__ == "__main__":
    unittest.main()