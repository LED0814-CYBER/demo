import os
import shutil
import sys
import unittest
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "module")))

from coarse_filter import CoarseFilterConfig, CoarseFilterEngine, build_lib_groups


class DummyObj:
    def __init__(self, classes_dict):
        self.classes_dict = classes_dict


def make_class_info(class_name: str, method_sig: str, strings):
    method_name = f"{class_name}.method"
    method_info = {
        method_name: [
            "md5",
            [1, 2, 3],
            list(strings),
            3,
            method_sig,
        ]
    }
    return [
        "class-md5",
        1,
        3,
        {},
        method_info,
        [method_sig],
        [],
        "desc",
    ]


class CoarseFilterTests(unittest.TestCase):
    def setUp(self):
        workspace_tmp = os.path.abspath(os.path.join(os.getcwd(), ".tmp_tests"))
        os.makedirs(workspace_tmp, exist_ok=True)
        self.temp_dir = os.path.join(workspace_tmp, f"coarse_filter_test_{uuid.uuid4().hex}")
        os.makedirs(self.temp_dir, exist_ok=True)
        self.lib_dex_folder = os.path.join(self.temp_dir, "tpl_dex")
        self.index_dir = os.path.join(self.temp_dir, "coarse_index")
        os.makedirs(self.lib_dex_folder, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _touch_family_versions(self, family, versions):
        family_dir = os.path.join(self.lib_dex_folder, family)
        os.makedirs(family_dir, exist_ok=True)
        rel_paths = []
        for ver in versions:
            file_name = f"{family}_{ver}.dex"
            abs_path = os.path.join(family_dir, file_name)
            with open(abs_path, "wb") as f:
                f.write((family + ver).encode("utf-8"))
            rel_paths.append(f"{family}/{file_name}")
        return rel_paths

    def _engine(self, loader, **cfg_kwargs):
        params = {
            "enabled": True,
            "score_threshold": 0.12,
            "top_k": 60,
            "minhash_perm": 64,
            "lsh_bands": 16,
            "lsh_rows": 4,
            "fallback_on_empty": True,
            "high_freq_ratio": 0.95,
            "high_freq_min_df": 999,
            "min_token_len": 3,
        }
        params.update(cfg_kwargs)
        config = CoarseFilterConfig(**params)
        return CoarseFilterEngine(
            lib_dex_folder=self.lib_dex_folder,
            load_lib_obj=loader,
            config=config,
            index_dir=self.index_dir,
        )

    def test_index_build_and_reload(self):
        alpha_rels = self._touch_family_versions("family.alpha", ["1.0.0", "2.0.0"])
        beta_rels = self._touch_family_versions("family.beta", ["1.0.0"])

        fake_libs = {
            alpha_rels[0]: DummyObj({
                "com.alpha.A": make_class_info("com.alpha.A", "alphaApiSig", ["alphaEndpoint"])  # noqa: E501
            }),
            alpha_rels[1]: DummyObj({
                "com.alpha.B": make_class_info("com.alpha.B", "alphaNewSig", ["alphaConfig"])  # noqa: E501
            }),
            beta_rels[0]: DummyObj({
                "com.beta.A": make_class_info("com.beta.A", "betaApiSig", ["betaEndpoint"])
            }),
        }

        def loader(rel_path):
            return fake_libs.get(rel_path)

        lib_groups = build_lib_groups(self.lib_dex_folder)
        engine = self._engine(loader)

        first = engine.ensure_index(lib_groups)
        self.assertEqual(first["total_families"], 2)
        self.assertEqual(first["rebuilt_families"], 2)

        second = engine.ensure_index(lib_groups)
        self.assertEqual(second["total_families"], 2)
        self.assertEqual(second["reused_families"], 2)
        self.assertEqual(second["rebuilt_families"], 0)

        self.assertTrue(os.path.exists(os.path.join(self.index_dir, "coarse_index.pkl")))

    def test_query_is_stable(self):
        alpha_rels = self._touch_family_versions("family.alpha", ["1.0.0", "2.0.0"])
        beta_rels = self._touch_family_versions("family.beta", ["1.0.0", "2.0.0"])

        fake_libs = {
            alpha_rels[0]: DummyObj({
                "com.alpha.A": make_class_info("com.alpha.A", "alphaApiSig", ["alphaEndpoint"])  # noqa: E501
            }),
            alpha_rels[1]: DummyObj({
                "com.alpha.B": make_class_info("com.alpha.B", "alphaFeatureSig", ["alphaStore"])  # noqa: E501
            }),
            beta_rels[0]: DummyObj({
                "com.beta.A": make_class_info("com.beta.A", "betaApiSig", ["betaEndpoint"])
            }),
            beta_rels[1]: DummyObj({
                "com.beta.B": make_class_info("com.beta.B", "betaFeatureSig", ["betaStore"])
            }),
        }

        lib_groups = build_lib_groups(self.lib_dex_folder)
        engine = self._engine(lambda rel_path: fake_libs.get(rel_path), top_k=1, score_threshold=0.15)
        engine.ensure_index(lib_groups)

        apk_obj = DummyObj({
            "com.alpha.Client": make_class_info(
                "com.alpha.Client",
                "alphaApiSig",
                ["alphaEndpoint", "alphaStore"],
            )
        })

        first_candidates, _ = engine.select_candidate_groups(apk_obj, lib_groups)
        second_candidates, _ = engine.select_candidate_groups(apk_obj, lib_groups)

        self.assertEqual(first_candidates, second_candidates)
        self.assertIn("family.alpha", first_candidates)

    def test_broken_dex_tolerance(self):
        ok_rels = self._touch_family_versions("family.ok", ["1.0.0"])
        broken_rels = self._touch_family_versions("family.broken", ["1.0.0"])

        fake_libs = {
            ok_rels[0]: DummyObj({
                "com.ok.A": make_class_info("com.ok.A", "okSig", ["okString"])
            }),
        }

        def loader(rel_path):
            if rel_path in broken_rels:
                raise RuntimeError("broken dex")
            return fake_libs.get(rel_path)

        lib_groups = build_lib_groups(self.lib_dex_folder)
        engine = self._engine(loader)

        stats = engine.ensure_index(lib_groups)
        self.assertEqual(stats["total_families"], 2)

        apk_obj = DummyObj({
            "com.ok.Client": make_class_info("com.ok.Client", "okSig", ["okString"])
        })
        candidates, metrics = engine.select_candidate_groups(apk_obj, lib_groups)

        self.assertIn("family.ok", candidates)
        self.assertTrue(metrics["coarse_candidate_groups"] >= 1)


if __name__ == "__main__":
    unittest.main()
