.DEFAULT_GOAL := all
sources = pyfireservicerota
venv = .venv/bin

.PHONY: .pre-commit  ## Check that pre-commit is installed
.pre-commit:
	@pre-commit -V || echo 'Please install pre-commit: https://pre-commit.com/'

.PHONY: install  ## Install linting tools and pre-commit hooks
install: .venv .pre-commit
	$(venv)/pip install -q ruff mypy isort black types-requests
	pre-commit install --install-hooks

.PHONY: format  ## Auto-format python source files
format: .venv
	$(venv)/isort $(sources)
	$(venv)/black -l 79 $(sources)
	$(venv)/ruff check $(sources)

.PHONY: lint  ## Lint python source files
lint: .venv
	$(venv)/isort --check-only $(sources)
	$(venv)/ruff check $(sources)
	$(venv)/black -l 79 $(sources) --check --diff
	$(venv)/mypy $(sources)

.PHONY: codespell  ## Use Codespell to do spellchecking
codespell: .pre-commit
	pre-commit run codespell --all-files

.PHONY: .venv  ## Create virtual environment with linting tools
.venv:
	python3 -m venv .venv --upgrade-deps
	$(venv)/pip install -q ruff mypy isort black types-requests

.PHONY: publish  ## Publish to PyPi
publish:
	$(venv)/pip install -q build twine
	python3 -m build
	twine upload dist/*

.PHONY: all  ## Run the standard set of checks performed in CI
all: lint codespell

.PHONY: clean  ## Clear local caches and build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -r {} +
	find . -type f -name '*.py[co]' -exec rm -f {} +
	find . -type f -name '*~' -exec rm -f {} +
	find . -type f -name '.*~' -exec rm -f {} +
	rm -rf .cache
	rm -rf .mypy_cache
	rm -rf .pdm-build
	rm -rf .pytest_cache
	rm -rf .ruff_cache
	rm -rf *.egg-info
	rm -rf build
	rm -rf dist
	rm -rf site

.PHONY: help  ## Display this message
help:
	@grep -E \
		'^.PHONY: .*?## .*$$' $(MAKEFILE_LIST) | \
		sort | \
		awk 'BEGIN {FS = ".PHONY: |## "}; {printf "\033[36m%-19s\033[0m %s\n", $$2, $$3}'
