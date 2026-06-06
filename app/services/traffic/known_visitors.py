from __future__ import annotations

from typing import Any

KNOWN_VISITORS_BY_IP: dict[str, dict[str, str]] = {
    "172.219.42.87": {
        "label": "Tony",
        "detail": "owner",
        "confidence": "confirmed",
    },
    "104.28.116.13": {
        "label": "Tony",
        "detail": "owner",
        "confidence": "confirmed",
    },
    "104.28.116.14": {
        "label": "Tony",
        "detail": "owner",
        "confidence": "confirmed",
    },
    "187.137.98.115": {
        "label": "Julio",
        "detail": "known player",
        "confidence": "confirmed",
    },
    "174.90.223.103": {
        "label": "Joe",
        "detail": "likely family",
        "confidence": "confirmed",
    },
    "68.131.37.96": {
        "label": "Jim",
        "detail": "known player",
        "confidence": "confirmed",
    },
}


def known_visitor_for_ip(ip: str | None) -> dict[str, str] | None:
    cleaned = (ip or "").strip()
    if not cleaned:
        return None
    return KNOWN_VISITORS_BY_IP.get(cleaned)


def apply_known_visitor_confirmation(session: dict[str, Any]) -> dict[str, str] | None:
    known_visitor = known_visitor_for_ip(session.get("ip"))
    if not known_visitor:
        return None

    # Do not let a confirmed-human registry override deliberately collapsed automation.
    if session.get("known_automation") or session.get("is_burst_cluster"):
        return known_visitor

    label = known_visitor["label"]
    detail = known_visitor["detail"]

    session["known_visitor_label"] = label
    session["known_visitor_detail"] = detail
    session["known_visitor_confirmed"] = True

    session["classification_state"] = "human_confirmed"
    session["human_confidence"] = max(int(session.get("human_confidence") or 0), 100)
    session["suspicious_score"] = min(int(session.get("suspicious_score") or 0), 5)

    reasons = session.get("classification_reasons")
    if not isinstance(reasons, list):
        reasons = []
    if "known_confirmed_visitor_ip" not in reasons:
        reasons.append("known_confirmed_visitor_ip")
    session["classification_reasons"] = reasons

    session["classification_summary"] = (
        f"Confirmed human: {label} is registered as a known visitor for this IP."
    )
    session["attention_label"] = "Known human"
    session["attention_summary"] = (
        f"{label} · {detail}. Traffic upgraded this session because the IP is in the known visitor registry."
    )
    session["data_confidence_label"] = "Confirmed"
    session["data_confidence_summary"] = (
        "This session has operator-confirmed human context from the known visitor registry."
    )

    return known_visitor
