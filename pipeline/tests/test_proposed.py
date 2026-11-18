import json
import tempfile
import unittest
from pathlib import Path

from pipeline.ga_only.operators import Gene
from pipeline.proposed.algorithm import (
    ProposedConfig,
    ProposedIndividual,
    ProposedRunner,
    assign_crowding_distance,
    calculate_2d_hypervolume,
    crowded_comparison,
    dominates,
    environmental_selection,
    fast_non_dominated_sort,
    parse_llm_genes,
)


class FakePool:
    operators = {"flatten": object(), "split": object(), "encode_arithmetic": object()}

    def transform(self, source, genes, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        active = [g for g in genes if g.operator != "noop"]
        destination.write_text(source.read_text(encoding="utf-8") + "\n// " + ",".join(g.operator for g in active), encoding="utf-8")
        return [{"operator": g.operator, "seed": g.seed} for g in active]


class ProposedAlgorithmTests(unittest.TestCase):
    def test_pareto_dominance(self):
        # Higher is better for both objectives
        ind_a = ProposedIndividual(genes=(), objectives=(0.9, 0.8))
        ind_b = ProposedIndividual(genes=(), objectives=(0.8, 0.7))
        ind_c = ProposedIndividual(genes=(), objectives=(0.7, 0.95))

        self.assertTrue(dominates(ind_a, ind_b))
        self.assertFalse(dominates(ind_b, ind_a))
        self.assertFalse(dominates(ind_a, ind_c))
        self.assertFalse(dominates(ind_c, ind_a))

    def test_fast_non_dominated_sort(self):
        ind1 = ProposedIndividual(genes=(), objectives=(0.9, 0.8))  # Front 1
        ind2 = ProposedIndividual(genes=(), objectives=(0.7, 0.95)) # Front 1
        ind3 = ProposedIndividual(genes=(), objectives=(0.8, 0.7))  # Front 2 (dominated by ind1)
        ind4 = ProposedIndividual(genes=(), objectives=(0.5, 0.5))  # Front 3

        pop = [ind1, ind2, ind3, ind4]
        fronts = fast_non_dominated_sort(pop)

        self.assertEqual(len(fronts), 3)
        self.assertEqual(set(fronts[0]), {ind1, ind2})
        self.assertEqual(fronts[1], [ind3])
        self.assertEqual(fronts[2], [ind4])
        self.assertEqual(ind1.rank, 1)
        self.assertEqual(ind3.rank, 2)
        self.assertEqual(ind4.rank, 3)

    def test_crowding_distance_and_comparison(self):
        ind1 = ProposedIndividual(genes=(), objectives=(0.1, 0.9), rank=1)
        ind2 = ProposedIndividual(genes=(), objectives=(0.5, 0.5), rank=1)
        ind3 = ProposedIndividual(genes=(), objectives=(0.9, 0.1), rank=1)

        front = [ind1, ind2, ind3]
        assign_crowding_distance(front)

        # Extreme solutions must receive infinite crowding distance
        self.assertEqual(ind1.crowding_distance, float("inf"))
        self.assertEqual(ind3.crowding_distance, float("inf"))
        self.assertTrue(math_finite := (0 < ind2.crowding_distance < float("inf")))

        # Boundary point preferred over interior point of same rank
        self.assertTrue(crowded_comparison(ind1, ind2))

    def test_environmental_selection(self):
        ind1 = ProposedIndividual(genes=(), objectives=(0.9, 0.8))  # Front 1
        ind2 = ProposedIndividual(genes=(), objectives=(0.7, 0.95)) # Front 1
        ind3 = ProposedIndividual(genes=(), objectives=(0.8, 0.7))  # Front 2
        ind4 = ProposedIndividual(genes=(), objectives=(0.2, 0.2))  # Front 3

        pop = [ind1, ind2, ind3, ind4]
        survivors = environmental_selection(pop, target_size=2)
        self.assertEqual(set(survivors), {ind1, ind2})

    def test_hypervolume_calculation(self):
        # Front with single point (0.8, 0.5) against (0,0) -> 0.8 * 0.5 = 0.4
        ind1 = ProposedIndividual(genes=(), objectives=(0.8, 0.5))
        self.assertAlmostEqual(calculate_2d_hypervolume([ind1]), 0.4)

        # Two non-dominated points: (0.4, 0.8) and (0.8, 0.4)
        # HV = 0.4 * 0.8 + (0.8 - 0.4) * 0.4 = 0.32 + 0.16 = 0.48
        ind2 = ProposedIndividual(genes=(), objectives=(0.4, 0.8))
        ind3 = ProposedIndividual(genes=(), objectives=(0.8, 0.4))
        self.assertAlmostEqual(calculate_2d_hypervolume([ind2, ind3]), 0.48)

    def test_parse_llm_genes(self):
        raw = '{"thought": "Disrupt CFG", "genes": [{"operator": "flatten", "seed": 100}, {"operator": "split", "seed": 200}]}'
        thought, genes = parse_llm_genes(raw, {"flatten", "split"}, chromosome_length=3)
        self.assertEqual(thought, "Disrupt CFG")
        self.assertEqual(len(genes), 3)
        self.assertEqual(genes[0].operator, "flatten")
        self.assertEqual(genes[1].operator, "split")
        self.assertEqual(genes[2].operator, "noop")

        # Robustness test: raw string gene list and dict without seed
        raw_robust = '{"thought": "Try operators", "genes": ["flatten", {"operator": "split"}]}'
        thought_r, genes_r = parse_llm_genes(raw_robust, {"flatten", "split"}, chromosome_length=2)
        self.assertEqual(thought_r, "Try operators")
        self.assertEqual(genes_r[0].operator, "flatten")
        self.assertEqual(genes_r[1].operator, "split")

    def test_proposed_runner_end_to_end_with_c2_stagnation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            output = root / "output"

            llm_called = 0
            def fake_generate(system, prompt, temp):
                nonlocal llm_called
                llm_called += 1
                return '{"thought": "Escape stagnation", "genes": [{"operator": "flatten", "seed": 1234}]}'

            # Evaluator returns constant fitness, causing deliberate stagnation
            def evaluate(path):
                return 0.55, {"build": "PASSED", "detectors": {"ember": {"status": "COMPLETED", "score": 0.45}}}

            config = ProposedConfig(
                population_size=4,
                generations=3,
                chromosome_length=2,
                stagnation_patience=1,  # Trigger quickly
                max_llm_calls=2,
                max_evaluations=20,
                seed=42,
            )

            runner = ProposedRunner(FakePool(), evaluate, fake_generate, config)
            result = runner.run(source, output)

            self.assertTrue(result["best_fitness"] > 0)
            self.assertTrue((output / "best.c").is_file())
            self.assertTrue((output / "result.json").is_file())
            self.assertTrue((output / "c2_decisions.jsonl").is_file())
            self.assertTrue((output / "evaluations.jsonl").is_file())

            # Verify C2 logged stagnation and triggered LLM
            c2_logs = [json.loads(line) for line in (output / "c2_decisions.jsonl").read_text().splitlines()]
            triggers = [log for log in c2_logs if "TRIGGER_LLM_STAGNATION" in log["action"]]
            self.assertTrue(len(triggers) >= 1)
            self.assertTrue(llm_called >= 1)
            self.assertTrue(result["llm_calls"] >= 1)

    def test_proposed_runner_custom_code_synthesis(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.c"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            output = root / "output"

            # LLM returns C code block instead of JSON genes
            def fake_generate(system, prompt, temp):
                return "Here is evasive code:\n```c\nint main(void) { /* evasive rewrite */ return 0; }\n```"

            def evaluate(path):
                content = Path(path).read_text(encoding="utf-8")
                if "/* evasive rewrite */" in content:
                    return 0.85, {"build": "PASSED", "detectors": {"ember": {"status": "COMPLETED", "score": 0.15}}}
                return 0.50, {"build": "PASSED", "detectors": {"ember": {"status": "COMPLETED", "score": 0.50}}}

            config = ProposedConfig(
                population_size=4,
                generations=2,
                chromosome_length=2,
                stagnation_patience=1,
                max_llm_calls=2,
                seed=42,
            )

            runner = ProposedRunner(FakePool(), evaluate, fake_generate, config)
            result = runner.run(source, output)

            self.assertEqual(result["best_fitness"], 0.85)
            self.assertIn("/* evasive rewrite */", (output / "best.c").read_text())
            self.assertEqual(result["best_origin"], "llm_stagnation_code")


if __name__ == "__main__":
    unittest.main()
