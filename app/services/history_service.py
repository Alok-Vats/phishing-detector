"""Persistence helpers for scan history records."""

from __future__ import annotations

import json

from app.db.database import execute_query, fetch_all


def save_scan_result(result: dict) -> None:
    """Persist a completed scan result for later review."""
    details = result.get("details", {})
    input_type = result.get("input_type", "url")
    input_value = result.get("url") if input_type == "url" else result.get("sender", "")
    normalized_value = (
        details.get("normalized_url", input_value)
        if input_type == "url"
        else details.get("normalized_sender", input_value)
    )
    execute_query(
        """
        INSERT INTO scan_history (
            input_type,
            input_value,
            normalized_value,
            prediction,
            confidence,
            matched_list,
            model_source,
            reasons,
            features,
            model_versions,
            threat_intel_results
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            input_type,
            input_value,
            normalized_value,
            result["prediction"],
            float(result["confidence"]),
            result.get("matched_list"),
            result.get("model_source", "heuristic"),
            json.dumps(result.get("reasons", [])),
            json.dumps(details.get("features", {})),
            json.dumps(result.get("model_versions", {})),
            json.dumps(result.get("reputation_sources", [])),
        ),
    )


def get_scan_history(
    limit: int = 50, 
    offset: int = 0,
    search: str = "",
    input_type: str = "",
    classification: str = "",
    min_confidence: float = 0.0,
    date_from: str = "",
    date_to: str = ""
) -> list[dict]:
    """Return filtered and paginated scan history records."""
    safe_limit = max(1, min(limit, 500))
    safe_offset = max(0, offset)
    
    query = """
        SELECT
            id,
            input_type,
            input_value,
            normalized_value,
            prediction,
            confidence,
            matched_list,
            model_source,
            reasons,
            features,
            model_versions,
            threat_intel_results,
            created_at
        FROM scan_history
        WHERE 1=1
    """
    params = []
    
    if search:
        query += " AND (input_value LIKE ? OR normalized_value LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    
    if input_type in ["url", "email"]:
        query += " AND input_type = ?"
        params.append(input_type)
        
    if classification in ["phishing", "suspicious", "legitimate"]:
        query += " AND prediction = ?"
        params.append(classification)
        
    if min_confidence > 0:
        query += " AND confidence >= ?"
        params.append(min_confidence)
        
    if date_from:
        query += " AND created_at >= ?"
        params.append(date_from)
        
    if date_to:
        query += " AND created_at <= ?"
        params.append(date_to + " 23:59:59")
        
    query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    params.extend([safe_limit, safe_offset])

    rows = fetch_all(query, tuple(params))

    records: list[dict] = []
    for row in rows:
        record = dict(row)
        try:
            record["reasons"] = json.loads(record["reasons"]) if record.get("reasons") else []
            record["features"] = json.loads(record["features"]) if record.get("features") else {}
            record["model_versions"] = json.loads(record["model_versions"]) if record.get("model_versions") else {}
            record["threat_intel_results"] = json.loads(record["threat_intel_results"]) if record.get("threat_intel_results") else []
        except:
            pass
        records.append(record)

    return records


def get_scan_by_id(scan_id: int) -> dict | None:
    from app.db.database import fetch_one
    row = fetch_one("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
    if not row:
        return None
    record = dict(row)
    try:
        record["reasons"] = json.loads(record["reasons"]) if record.get("reasons") else []
        record["features"] = json.loads(record["features"]) if record.get("features") else {}
        record["model_versions"] = json.loads(record["model_versions"]) if record.get("model_versions") else {}
        record["threat_intel_results"] = json.loads(record["threat_intel_results"]) if record.get("threat_intel_results") else []
    except:
        pass
    return record

