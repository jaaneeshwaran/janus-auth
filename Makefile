.PHONY: setup lint typecheck test benchmark demo clean

setup:
	@test -d .venv || python3.12 -m venv .venv
	.venv/bin/python -m pip install -e ".[dev]"

lint:
	.venv/bin/ruff check src/ tests/

typecheck:
	.venv/bin/mypy src/

test:
	.venv/bin/pytest -v --tb=short tests/

benchmark:
	.venv/bin/janus-auth benchmark --runs 5 --budget 300 --out-dir artifacts/benchmark/

demo:
	.venv/bin/janus-auth demo --out-dir artifacts/demo/

clean:
	rm -rf artifacts/ *.sqlite3* .pytest_cache .mypy_cache .ruff_cache build/ dist/ *.egg-info src/*.egg-info
