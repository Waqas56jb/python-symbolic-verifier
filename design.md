
# Design Document: PyVeriCheck
## Overview
Implements a Python frontend for ESBMC, performing symbolic model checking with Z3.
## Architecture
- Parser: Converts code to AST, exports JSON.
- TypeChecker: Adds PEP 484 annotations.
- IRConverter: Builds symbol table and CFG (mock IRep).
- ESBMCWrapper: Mocks ESBMC verification.
- SMTSolver: Uses Z3 for constraints.
- VulnerabilityChecker: Checks all vulnerabilities.
- CorrectnessChecker: Measures code safety.
- Benchmark: Measures performance.
- UI: Displays results in a user-friendly interface.
## Workflow
1. Parse to AST and JSON.
2. Annotate types.
3. Convert to symbol table/CFG.
4. Verify with ESBMC (mock).
5. Check vulnerabilities.
6. Measure correctness.
7. Benchmark.
8. Generate reports (text, HTML, JSON).
9. Display in UI.
