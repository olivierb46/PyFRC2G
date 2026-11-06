"""
Risk score (0-100) computed from audit findings, globally and per interface, with its
evolution between runs (<output>/risk_history.json).

score = sum(weight[severity]) over findings, LOW findings counting for 10 points at most,
capped at 100. Default weights: CRITICAL 25, HIGH 10, MEDIUM 4, LOW 1.
"""

import json
import logging
import os

from pyfrc2g.model.rules import interface_part

DEFAULT_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
LOW_CAP = 10
LEVELS = ((60, "CRITICAL"), (30, "HIGH"), (10, "MODERATE"), (0, "LOW"))
HISTORY_SIZE = 100


def score(findings, weights=None):
    weights = weights or DEFAULT_WEIGHTS
    total, low = 0, 0
    for finding in findings:
        weight = weights.get(finding.get("SEVERITY"), 0)
        if finding.get("SEVERITY") == "LOW":
            low += weight
        else:
            total += weight
    return min(100, total + min(low, LOW_CAP))


def level(value):
    for threshold, name in LEVELS:
        if value >= threshold:
            return name
    return "LOW"


def compute(findings, weights=None, history_path=None, generated_at=""):
    """
    Returns:
        dict: {"score", "level", "previous", "delta", "by_interface": {iface: score},
               "history": [{"date", "score"}...]}
    """
    by_iface = {}
    for finding in findings:
        by_iface.setdefault(interface_part(finding.get("GATEWAY", "")), []).append(finding)
    result = {
        "score": score(findings, weights),
        "by_interface": {iface: score(items, weights) for iface, items in sorted(by_iface.items())},
        "previous": None, "delta": None, "history": [],
    }
    result["level"] = level(result["score"])

    if history_path:
        history = []
        if os.path.isfile(history_path):
            try:
                with open(history_path, encoding="utf-8") as f:
                    history = json.load(f)
            except (OSError, ValueError) as e:
                logging.warning(f"Ignoring unreadable risk history {history_path}: {e}")
        if history:
            result["previous"] = history[-1].get("score")
            result["delta"] = result["score"] - result["previous"]
        history.append({"date": generated_at, "score": result["score"],
                        "by_interface": result["by_interface"]})
        history = history[-HISTORY_SIZE:]
        result["history"] = history
        os.makedirs(os.path.dirname(history_path) or ".", exist_ok=True)
        with open(history_path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=1)
    return result


def describe(risk):
    """'42/100 (HIGH, +5 since previous run)'."""
    if not risk:
        return ""
    text = f"{risk['score']}/100 ({risk['level']}"
    if risk.get("delta") is not None:
        text += f", {risk['delta']:+d} since previous run"
    return text + ")"
