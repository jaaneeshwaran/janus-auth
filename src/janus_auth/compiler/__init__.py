"""Counterfactual synthesis and workflow-compilation components for Janus-Auth."""

from janus_auth.compiler.compiler import (
    MAX_MANIFEST_BYTES,
    PairPreservationError,
    WorkflowCompiler,
    assert_pair_preserved,
    canary_for,
    load_manifest,
)
from janus_auth.compiler.mapper import HeuristicOperationMapper
from janus_auth.compiler.z3_synthesizer import (
    InfeasibleObligation,
    PolicyEncodingDivergenceError,
    SynthesisReport,
    Z3Synthesizer,
)

__all__ = [
    "MAX_MANIFEST_BYTES",
    "HeuristicOperationMapper",
    "InfeasibleObligation",
    "PairPreservationError",
    "PolicyEncodingDivergenceError",
    "SynthesisReport",
    "WorkflowCompiler",
    "Z3Synthesizer",
    "assert_pair_preserved",
    "canary_for",
    "load_manifest",
]
