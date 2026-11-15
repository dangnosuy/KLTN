import json
import tempfile
import unittest
from pathlib import Path

from pipeline.ga_only.operators import Gene
from pipeline.heuristic.algorithm import HeuristicRunner, Recipe


class FakePool:
    operators = {"first": object(), "second": object()}

    def transform(self, source, genes, destination):
        gene = genes[0]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source.read_text(encoding="utf-8") + f"\n/* {gene.operator}:{gene.seed} */", encoding="utf-8")
        return [{"operator": gene.operator, "seed": gene.seed}]


class HeuristicTests(unittest.TestCase):
    def test_fixed_recipe_preserves_stages_and_scores_final_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }", encoding="utf-8")
            recipe = Recipe("fixed", (Gene("first", 1), Gene("second", 2)))
            result = HeuristicRunner(FakePool(), lambda path: (0.75, {"length": len(path.read_text())})).run(source, recipe, root / "output")
            self.assertEqual(result["fitness"], 0.75)
            self.assertEqual([step["operator"] for step in result["steps"]], ["first", "second"])
            self.assertTrue((root / "output" / "stages" / "stage-001-first.c").is_file())
            self.assertIn("second:2", (root / "output" / "final.c").read_text())

    def test_recipe_validation_and_unknown_operator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recipe_path = root / "recipe.json"
            recipe_path.write_text(json.dumps({"name": "x", "steps": [{"operator": "missing", "seed": 1}]}), encoding="utf-8")
            recipe = Recipe.load(recipe_path)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unknown recipe operators"):
                HeuristicRunner(FakePool(), lambda _path: (0.0, {})).run(source, recipe, root / "output")


if __name__ == "__main__":
    unittest.main()
