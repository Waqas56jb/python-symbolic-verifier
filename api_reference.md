
# API Reference: PyVeriCheck
## Parser
- parse_to_ast(): Parse code to AST, returns success boolean.
- ast_to_json(): Export JSON AST.
- get_control_structures(): List control structures.
- get_oop_elements(): List OOP elements.
## TypeChecker
- annotate_types(): Add PEP 484 annotations.
- apply_annotations_to_json(): Annotate JSON AST.
## IRConverter
- build_symbol_table(): Generate symbol table.
- build_cfg(): Generate CFG.
## ESBMCWrapper
- run_verification(): Mock verification.
## SMTSolver
- add_constraint(): Add constraint.
- check(): Check satisfiability.
- reset(): Clear constraints.
## VulnerabilityChecker
- check_all(): Run all vulnerability checks.
## CorrectnessChecker
- count_checks(): Count total and failed checks.
- get_correctness_score(): Calculate safety percentage.
- get_summary(): Return correctness summary.
## Benchmark
- run_benchmark(): Measure performance.
## VerificationUI
- run(): Display results in GUI.
## Report Generator
- generate_reports(): Create text and HTML reports.
