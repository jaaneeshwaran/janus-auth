"""Isolated dual-branch execution of compiled counterfactual twin plans.

Every request — including the reset — is admitted by
:class:`~janus_auth.security.gatekeeper.SafetyGatekeeper` before the HTTP client sees it.
Branch A and Branch B each start from a fresh reset and never share a placeholder context.
The executor records redacted :class:`~janus_auth.models.StepObservation` values and returns
typed :class:`~janus_auth.models.PairedExecutionEvidence` for adjudication.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from typing import Any, Final

import httpx

from janus_auth.models import (
    ApiStep,
    BranchLabel,
    BranchTrace,
    CompiledTwinPlan,
    ExpectedRole,
    PairedExecutionEvidence,
    StepObservation,
)
from janus_auth.security.gatekeeper import (
    RateLimitExceededError,
    SafetyGatekeeper,
)
from janus_auth.security.redactor import Redactor
from janus_auth.security.store import TraceStore

_PLACEHOLDER: Final[re.Pattern[str]] = re.compile(r"\{([A-Za-z0-9_]+)\}")
_DEFAULT_MAX_ATTEMPTS: Final[int] = 4


class ExecutionError(RuntimeError):
    """Raised when evidence cannot be produced for a plan at all."""


def _dotted_get(payload: Any, path: str) -> Any:
    current = payload
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _render(template: str, context: dict[str, str]) -> str | None:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = context.get(name)
        if value is None:
            raise KeyError(name)
        return value

    try:
        return _PLACEHOLDER.sub(replace, template)
    except KeyError:
        return None


class CounterfactualExecutor:
    """Execute both branches of a compiled plan from independent clean resets."""

    def __init__(
        self,
        client: httpx.Client,
        gatekeeper: SafetyGatekeeper,
        *,
        base_url: str | None = None,
        mode: str = "clean",
        trace_store: TraceStore | None = None,
    ) -> None:
        if client.follow_redirects:
            raise ValueError("executor client must not follow redirects")
        self._client = client
        self._gatekeeper = gatekeeper
        self._base_url = (base_url or str(client.base_url)).rstrip("/")
        if not self._base_url:
            raise ValueError("executor requires an absolute base URL")
        self._mode = mode
        self._trace_store = trace_store

    @property
    def requests_used(self) -> int:
        return self._gatekeeper.requests_used

    def execute(self, plan: CompiledTwinPlan) -> PairedExecutionEvidence:
        """Run both branches and return paired, independently reset evidence."""
        started_at = datetime.now(UTC)
        branch_a, epoch_a = self._execute_branch(
            plan, plan.branch_a_steps, "A"
        )
        branch_b, epoch_b = self._execute_branch(
            plan, plan.branch_b_steps, "B"
        )
        evidence = PairedExecutionEvidence(
            plan_id=plan.plan_id,
            branch_a=branch_a,
            branch_b=branch_b,
            branch_a_reset_epoch=epoch_a,
            branch_b_reset_epoch=epoch_b,
        )
        if self._trace_store is not None:
            self._trace_store.record_run(
                f"run-{plan.plan_id}",
                started_at,
                self._gatekeeper.manifest.policy_sha256,
                self._gatekeeper.manifest.manifest_sha256,
                self._base_url,
                total_requests=self.requests_used,
            )
        return evidence

    def _token_for(self, alias: str) -> str:
        token = self._gatekeeper.manifest.principal_aliases.get(alias)
        if not token:
            raise ExecutionError(f"manifest declares no credential alias for {alias!r}")
        return token

    def _url_for(self, step: ApiStep, context: dict[str, str]) -> str | None:
        path = _render(step.path_template, context)
        if path is None:
            return None
        query: dict[str, str] = {}
        for key, value in step.query.items():
            rendered = _render(value, context)
            if rendered is None:
                return None
            query[key] = rendered
        url = httpx.URL(f"{self._base_url}{path}")
        if query:
            url = url.copy_merge_params(query)
        return str(url)

    def _admit(self, url: str, method: str) -> None:
        for attempt in range(_DEFAULT_MAX_ATTEMPTS):
            try:
                self._gatekeeper.validate_request(url, method)
                return
            except RateLimitExceededError:
                if attempt == _DEFAULT_MAX_ATTEMPTS - 1:
                    raise
                time.sleep(1.0 / float(self._gatekeeper.manifest.rate_limit_rps))

    def _execute_branch(
        self,
        plan: CompiledTwinPlan,
        steps: list[ApiStep],
        branch: BranchLabel,
    ) -> tuple[BranchTrace, int]:
        context: dict[str, str] = {"canary": plan.canary}
        observations: list[StepObservation] = []
        pre_witness_ok = False
        post_witness_ok = False
        reset_epoch = 0
        reset_ok = False
        transition_ok = False
        probe: StepObservation | None = None
        effect_witness: StepObservation | None = None
        valid = True

        for step in steps:
            url = self._url_for(step, context)
            if url is None:
                valid = False
                break
            if (
                step.expected_role is ExpectedRole.PROBE
                and plan.synthesized.consistency_bound_ms > 0
            ):
                time.sleep(plan.synthesized.consistency_bound_ms / 1000.0)
            body = dict(step.json_body) if step.json_body is not None else None
            if step.step_id == "reset":
                body = {"vulnerability_mode": self._mode}
            observation = self._send(step, url, body)
            observations.append(observation)
            if observation.error is not None:
                valid = False
                break

            if step.step_id == "reset":
                parsed: object = observation.parsed_json
                raw_epoch = parsed.get("epoch") if isinstance(parsed, dict) else None
                epoch = _as_int(raw_epoch)
                reset_ok = observation.status_code == 200 and epoch is not None
                if epoch is not None:
                    reset_epoch = epoch
            elif step.extract:
                parsed = observation.parsed_json
                for placeholder, json_path in step.extract.items():
                    value = _dotted_get(parsed, json_path)
                    if value is None or not isinstance(value, (str, int)):
                        valid = False
                        break
                    context[placeholder] = str(value)
                if not valid:
                    break

            if step.expected_role is ExpectedRole.PRE_WITNESS:
                pre_witness_ok = (
                    observation.status_code == 200 and observation.canary_present
                )
            elif step.expected_role is ExpectedRole.TRANSITION:
                transition_ok = 200 <= observation.status_code < 300
            elif step.expected_role is ExpectedRole.POST_TRANSITION_WITNESS:
                post_witness_ok = observation.status_code == 200
            elif step.expected_role is ExpectedRole.PROBE:
                probe = observation
            elif step.expected_role is ExpectedRole.EFFECT_WITNESS:
                effect_witness = observation

        valid = (
            valid
            and reset_ok
            and pre_witness_ok
            and transition_ok
            and post_witness_ok
            and probe is not None
            and effect_witness is not None
        )
        trace = BranchTrace(
            branch=branch,
            plan_id=plan.plan_id,
            steps=observations,
            pre_witness_ok=pre_witness_ok,
            post_transition_witness_ok=post_witness_ok,
            probe=probe,
            effect_witness=effect_witness,
            canary=plan.canary,
            valid=valid,
        )
        return trace, reset_epoch

    def _send(
        self,
        step: ApiStep,
        url: str,
        body: dict[str, Any] | None,
    ) -> StepObservation:
        token = self._token_for(step.principal_alias)
        headers = {"Authorization": f"Bearer {token}"}
        started = time.perf_counter()
        try:
            self._admit(url, step.method)
            response = self._client.request(
                step.method,
                url,
                headers=headers,
                json=body,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            return StepObservation(
                step_id=step.step_id,
                method=step.method,
                path=httpx.URL(url).path,
                principal_alias=step.principal_alias,
                status_code=0,
                elapsed_ms=(time.perf_counter() - started) * 1000.0,
                error=f"{type(exc).__name__}: request failed before a response",
            )
        elapsed = (time.perf_counter() - started) * 1000.0
        try:
            parsed: Any = response.json()
        except ValueError:
            parsed = None
        text = response.text
        return StepObservation(
            step_id=step.step_id,
            method=step.method,
            path=httpx.URL(url).path,
            principal_alias=step.principal_alias,
            status_code=response.status_code,
            parsed_json=parsed,
            headers=Redactor.redact_headers(dict(response.headers)),
            elapsed_ms=elapsed,
            canary_present="JANUS_CANARY_" in text,
        )


__all__ = ["CounterfactualExecutor", "ExecutionError"]
