"""Detector D — firmware integrity.

Independently re-hashes the firmware components against a SHA-256
manifest (via :class:`~aegisflight.integrity.verifier.FirmwareVerifier`) for
file-based / Stage-1 checks, and/or checks observed ``AUTOPILOT_VERSION``
telemetry against a pinned :class:`~aegisflight.integrity.allowlist.FirmwareAllowlist`
for live MAVLink links (#20).
"""

from __future__ import annotations

from typing import Any

from ..core.enums import AttackType, DetectorName, IntegrityStatus
from ..core.types import DetectorResult
from ..integrity.allowlist import FirmwareAllowlist
from ..integrity.verifier import FirmwareVerifier, IntegrityReport
from .base import Detector


class IntegrityDetector(Detector):
    name = DetectorName.INTEGRITY

    def __init__(
        self,
        verifier: FirmwareVerifier | None = None,
        recheck_every: int = 5,
        allowlist: FirmwareAllowlist | None = None,
    ) -> None:
        self.verifier = verifier
        self.recheck_every = max(1, recheck_every)
        self.allowlist = allowlist
        self._n = 0
        self._cached: IntegrityReport | None = None
        self._observed_versions: dict[tuple[int, int], tuple[int, dict[str, Any]]] = {}
        self._coverage_emitted = False

    def observe_message(
        self,
        msgname: str,
        fields: dict[str, Any],
        sysid: int = 1,
        compid: int = 1,
    ) -> None:
        """Record observed ``AUTOPILOT_VERSION`` messages for allowlist verification."""
        if msgname == "AUTOPILOT_VERSION":
            self._observed_versions[(int(sysid), int(compid))] = (self._n, dict(fields))

    def _verifier_report(self) -> IntegrityReport | None:
        if self.verifier is None:
            return None
        if self._cached is None or self._n % self.recheck_every == 0:
            self._cached = self.verifier.verify()
        return self._cached

    def _allowlist_report(self) -> IntegrityReport | None:
        if self.allowlist is None or not self.allowlist.entries:
            return None
        if not self._observed_versions:
            return IntegrityReport(
                status=IntegrityStatus.UNKNOWN,
                evidence=["coverage: AUTOPILOT_VERSION not observed"],
            )
        mismatches: list[str] = []
        valid_evidence: list[str] = []
        coverage_notes: list[str] = []
        checked = 0
        any_valid = False
        for (sysid, compid), (_, fields) in sorted(self._observed_versions.items()):
            rep = self.allowlist.verify_autopilot_version(fields, sysid=sysid, compid=compid)
            checked += rep.checked
            if rep.status is IntegrityStatus.INVALID:
                mismatches.extend(rep.evidence)
            elif rep.status is IntegrityStatus.VALID:
                any_valid = True
                valid_evidence.extend(rep.evidence)
            else:
                coverage_notes.extend(rep.evidence)
        if mismatches:
            return IntegrityReport(
                status=IntegrityStatus.INVALID,
                checked=checked,
                tampered=mismatches,
                evidence=mismatches,
            )
        if any_valid:
            return IntegrityReport(
                status=IntegrityStatus.VALID,
                checked=checked,
                evidence=valid_evidence + coverage_notes,
            )
        return IntegrityReport(
            status=IntegrityStatus.UNKNOWN,
            checked=checked,
            evidence=coverage_notes or ["coverage: AUTOPILOT_VERSION not verified"],
        )

    def _report(self) -> IntegrityReport:
        vrep = self._verifier_report()
        arep = self._allowlist_report()
        if vrep is None and arep is None:
            return IntegrityReport(status=IntegrityStatus.UNKNOWN, evidence=["no verifier configured"])
        if vrep is not None and arep is None:
            return vrep
        if arep is not None and vrep is None:
            return arep
        assert vrep is not None and arep is not None
        if vrep.status is IntegrityStatus.INVALID or arep.status is IntegrityStatus.INVALID:
            ev = (vrep.evidence if vrep.status is IntegrityStatus.INVALID else []) + (
                arep.evidence if arep.status is IntegrityStatus.INVALID else []
            )
            return IntegrityReport(
                status=IntegrityStatus.INVALID,
                checked=vrep.checked + arep.checked,
                tampered=vrep.tampered + arep.tampered,
                missing=vrep.missing,
                unexpected=vrep.unexpected,
                evidence=ev,
            )
        status = vrep.status if vrep.status is IntegrityStatus.VALID else arep.status
        return IntegrityReport(
            status=status,
            checked=vrep.checked + arep.checked,
            evidence=arep.evidence,
        )

    def process(self, frame=None) -> DetectorResult:
        self._n += 1
        report = self._report()
        triggered = report.status is IntegrityStatus.INVALID
        score = 1.0 if triggered else 0.0
        # Preserve exact SIM Stage-1 evidence=[] when allowlist is absent and not triggered;
        # expose coverage notes when allowlist checking is active.
        if triggered:
            ev = report.evidence
        elif self.allowlist is not None and self.allowlist.entries and not self._coverage_emitted:
            ev = [e for e in report.evidence if e.startswith("coverage:")]
            if ev:
                self._coverage_emitted = True
        else:
            ev = []
        return DetectorResult(
            detector=self.name,
            score=score,
            triggered=triggered,
            evidence=ev,
            attack_votes={AttackType.FIRMWARE_INTEGRITY: score} if triggered else {},
            signals={"integrity_invalid": float(triggered)},
        )

    @property
    def status(self) -> IntegrityStatus:
        return self._report().status

    def reset(self) -> None:
        self._n = 0
        self._cached = None
        self._observed_versions.clear()
