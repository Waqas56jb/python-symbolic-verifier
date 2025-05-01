
# Design Document: PyVeriCheck
## Overview
Implements a Python frontend for ESBMC, performing symbolic model checking with Z3.
## Architecture
- Parser: Converts user-input code to AST, exports JSON, handles syntax errors.
- TypeChecker: Adds PEP 484 annotations.
- IRConverter: Builds symbol table and CFG (mock IRep).
- ESBMCWrapper: Mocks ESBMC verification.
- SMTSolver: Uses Z3 for constraints.
- VulnerabilityChecker: Checks all vulnerabilities.
- CorrectnessChecker: Measures code safety.
- Benchmark: Measures performance.
- UI: Displays results in a user-friendly interface.
## Workflow
1. Get user input or use default code.
2. Parse to AST and JSON, handle errors.
3. Annotate types.
4. Convert to symbol table/CFG.
5. Verify with ESBMC (mock).
6. Check vulnerabilities.
7. Measure correctness.
8. Benchmark.
9. Generate reports (text, HTML, JSON).
10. Display in UI.
