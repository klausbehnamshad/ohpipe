"""Journalabgeleitete, workspaceweite B3b-Instanzregistersicht."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from collections.abc import Iterable

from .token import validate_label, validate_model_value, validate_token

__all__ = ["Instance", "InstanceRegistry", "InstanceRegistryError"]


class InstanceRegistryError(ValueError):
    pass


@dataclass(frozen=True)
class Instance:
    coder_id: str
    source: str
    label: str
    model: str | None = None
    parametersatz: str | None = None
    retired: bool = False
    event_digest: str | None = None

    def public_view(self) -> dict[str, str]:
        out = {"coder_id": self.coder_id, "source": self.source, "label": self.label}
        if self.source == "maschine":
            assert self.model is not None and self.parametersatz is not None
            out.update(model=self.model, parametersatz=self.parametersatz)
        return out

    @property
    def state_sha256(self) -> str:
        raw = {**self.public_view(), "retired": self.retired}
        blob = json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class InstanceRegistry:
    def __init__(self, instances: dict[str, Instance] | None = None) -> None:
        self._instances = dict(instances or {})

    @staticmethod
    def registration_payload(
        coder_id: str,
        *,
        source: str,
        label: str,
        reference: str,
        model: str | None = None,
        parametersatz: str | None = None,
    ) -> dict[str, str]:
        coder = validate_token(coder_id, field="coder_id")
        ref = validate_token(reference, field="reference")
        alias = validate_label(label)
        if source not in {"mensch", "maschine"}:
            raise InstanceRegistryError("source ist geschlossen auf mensch oder maschine")
        payload = {"coder_id": coder, "source": source, "label": alias, "reference": ref}
        if source == "mensch":
            if model is not None or parametersatz is not None:
                raise InstanceRegistryError("mensch verbietet model und parametersatz")
            return payload
        if model is None or parametersatz is None:
            raise InstanceRegistryError("maschine verlangt model und parametersatz")
        payload["model"] = validate_model_value(model, field="model")
        payload["parametersatz"] = validate_model_value(parametersatz, field="parametersatz")
        return payload

    @staticmethod
    def retirement_payload(coder_id: str, *, reference: str) -> dict[str, str]:
        return {
            "coder_id": validate_token(coder_id, field="coder_id"),
            "reference": validate_token(reference, field="reference"),
        }

    def register(self, payload: dict[str, str], *, event_digest: str | None = None) -> bool:
        expected = {"coder_id", "source", "label", "reference"}
        if payload.get("source") == "maschine":
            expected |= {"model", "parametersatz"}
        if set(payload) != expected:
            raise InstanceRegistryError(
                "instance.registered hat einen fehlenden oder fremden Feldsatz"
            )
        clean = self.registration_payload(**payload)
        coder = clean["coder_id"]
        previous = self._instances.get(coder)
        candidate = Instance(
            coder_id=coder,
            source=clean["source"],
            label=clean["label"],
            model=clean.get("model"),
            parametersatz=clean.get("parametersatz"),
            event_digest=event_digest,
        )
        if previous is not None:
            if previous.retired or previous.public_view() != candidate.public_view():
                raise InstanceRegistryError("coder_id ist bereits anders gebunden oder retired")
            return False
        self._instances[coder] = candidate
        return True

    def retire(self, payload: dict[str, str], *, event_digest: str | None = None) -> bool:
        if set(payload) != {"coder_id", "reference"}:
            raise InstanceRegistryError(
                "instance.retired hat einen fehlenden oder fremden Feldsatz"
            )
        clean = self.retirement_payload(**payload)
        previous = self._instances.get(clean["coder_id"])
        if previous is None:
            raise InstanceRegistryError("unbekannte coder_id kann nicht retired werden")
        if previous.retired:
            return False
        self._instances[previous.coder_id] = Instance(
            **previous.public_view(), retired=True, event_digest=event_digest
        )
        return True

    def get(self, coder_id: str, *, active: bool = False) -> Instance:
        coder = validate_token(coder_id, field="coder_id")
        item = self._instances.get(coder)
        if item is None:
            raise InstanceRegistryError("coder_id ist unbekannt")
        if active and item.retired:
            raise InstanceRegistryError("coder_id ist retired")
        return item

    def active_humans(self) -> tuple[Instance, ...]:
        return tuple(
            sorted(
                (
                    item
                    for item in self._instances.values()
                    if not item.retired and item.source == "mensch"
                ),
                key=lambda item: item.coder_id.encode("ascii"),
            )
        )

    @classmethod
    def from_events(cls, events: Iterable[Any]) -> InstanceRegistry:
        registry = cls()
        last_seq = 0
        for event in events:
            seq = getattr(event, "seq", 0)
            if not isinstance(seq, int) or isinstance(seq, bool) or seq <= last_seq:
                raise InstanceRegistryError("Registerordnung folgt strikt steigender seq")
            last_seq = seq
            if event.kind == "instance.registered":
                registry.register(dict(event.payload), event_digest=event.digest)
            elif event.kind == "instance.retired":
                registry.retire(dict(event.payload), event_digest=event.digest)
        return registry
