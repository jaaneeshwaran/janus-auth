"""Janus-Auth: an SMT-guided counterfactual differential compiler for API authorization lifecycles.

Importing this package is side-effect free: it performs no network calls, no filesystem
reads or writes, and no environment mutation. Only the package version is exposed here;
every functional module (models, security, oracle, compiler, runner, reporting, targets,
benchmark, CLI) is imported explicitly by its consumer.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
