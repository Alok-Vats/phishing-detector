"""Dashboard and metrics service."""

from __future__ import annotations

from app.db.database import fetch_all, fetch_one


def get_dashboard_metrics() -> dict:
    """Aggregate core metrics for the admin dashboard."""
    # Total Scans
    total_scans = fetch_one("SELECT COUNT(*) as count FROM scan_history")["count"]
    
    # Input Type Distribution
    types = fetch_all("SELECT input_type, COUNT(*) as count FROM scan_history GROUP BY input_type")
    type_counts = {row["input_type"]: row["count"] for row in types}
    
    # Classification Distribution
    classes = fetch_all("SELECT prediction, COUNT(*) as count FROM scan_history GROUP BY prediction")
    class_counts = {row["prediction"]: row["count"] for row in classes}
    
    # Recent Threats
    recent_threats = fetch_all("""
        SELECT id, input_type, normalized_value, created_at, confidence 
        FROM scan_history 
        WHERE prediction = 'phishing' 
        ORDER BY created_at DESC LIMIT 5
    """)
    
    # User Feedback Stats
    feedback = fetch_one("""
        SELECT 
            COUNT(*) as total, 
            SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) as correct
        FROM user_feedback
    """)
    feedback_accuracy = (feedback["correct"] / feedback["total"] * 100) if feedback["total"] and feedback["total"] > 0 else 0
    
    return {
        "total_scans": total_scans,
        "url_scans": type_counts.get("url", 0),
        "email_scans": type_counts.get("email", 0),
        "phishing_detections": class_counts.get("phishing", 0),
        "suspicious_detections": class_counts.get("suspicious", 0),
        "legitimate_detections": class_counts.get("legitimate", 0),
        "recent_threats": [dict(r) for r in recent_threats],
        "feedback_accuracy": feedback_accuracy,
        "total_feedback": feedback["total"] or 0
    }
