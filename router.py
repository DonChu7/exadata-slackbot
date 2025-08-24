# router.py
from typing import Dict, Any, List, Tuple, Optional
import re

class Router:
    def __init__(self):
        self.tools: List[Dict[str, Any]] = []        # [{service,name,desc,keywords,confidence_hint}]
        self.compiled: List[Tuple[re.Pattern, Dict[str,Any]]] = []  # [(regex, entry)]

    def load_from_manifests(self, manifests: List[Dict[str, Any]]):
        self.tools.clear()
        self.compiled.clear()

        for m in manifests or []:
            svc = m.get("service")
            for t in (m.get("tools") or []):
                intents = t.get("intents") or {}
                # intents can be a dict (preferred) or a list (legacy)
                if isinstance(intents, dict):
                    patterns = intents.get("patterns", []) or []
                    keywords = intents.get("keywords", []) or []
                    confidence_hint = intents.get("confidence_hint", 0.8)
                else:
                    # legacy: a bare list is treated as keywords
                    patterns = []
                    keywords = intents or []
                    confidence_hint = 0.8

                entry = {
                    "service": svc,
                    "name": t.get("name"),
                    "desc": t.get("description", ""),
                    "keywords": [k.lower() for k in keywords if isinstance(k, str)],
                    "confidence_hint": float(confidence_hint) if confidence_hint is not None else 0.8,
                }
                self.tools.append(entry)

                for pat in patterns:
                    try:
                        rx = re.compile(pat, re.I | re.DOTALL)
                        self.compiled.append((rx, entry))
                    except re.error:
                        # skip bad regex to avoid breaking the router
                        pass

    def rule_route(self, text: str) -> Optional[Dict[str, Any]]:
        low = (text or "").lower()

        # 1) Regex matches (highest confidence)
        for rx, entry in self.compiled:
            if rx.search(text or ""):
                return {
                    "tool": entry["name"],
                    "service": entry["service"],
                    "confidence": max(0.85, entry.get("confidence_hint", 0.85)),
                    "reason": f"regex:{rx.pattern}",
                }

        # 2) Keyword hints (lower confidence)
        for entry in self.tools:
            kws = entry.get("keywords") or []
            if kws and any(k in low for k in kws):
                return {
                    "tool": entry["name"],
                    "service": entry["service"],
                    "confidence": min(0.8, entry.get("confidence_hint", 0.8)),
                    "reason": "keyword",
                }

        return None