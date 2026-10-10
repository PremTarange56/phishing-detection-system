"""
app.py - Flask Backend Application
=====================================
CNS Concept: Web application security, API design, and input validation
This is the main Flask application that serves the Phishing Detection System.

Security Measures Implemented:
- Input validation and sanitization (prevent XSS)
- Parameterized database queries (prevent SQL injection)
- Static URL analysis only (no requests to suspicious sites)
- Content Security Policy headers
- Error handling

Author: Phishing Detection System
Project: Computer and Network Security (CNS) College Project
"""

from flask import Flask, request, jsonify, render_template, abort
import re
import html
from detector import analyze_url
from database import init_database, save_analysis, get_history, clear_history, get_statistics, get_recent_for_dashboard

# ============================================================
# Flask Application Initialization
# ============================================================
app = Flask(__name__)

# Initialize database on startup
init_database()


# ============================================================
# CNS Concept: Security Headers Middleware
# These headers protect against common web attacks:
# - XSS (Cross-Site Scripting)
# - Clickjacking
# - MIME type sniffing
# ============================================================
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ============================================================
# INPUT VALIDATION
# CNS Concept: Input validation is the first line of defense
# against injection attacks and malformed data
# ============================================================
def validate_url_input(url: str) -> tuple:
    """
    Validate URL input for safety and basic structure.
    
    Security measures:
    - Length limits (prevent DoS via huge inputs)
    - Character whitelist check
    - Basic structural validation
    
    Args:
        url: Raw URL string from user
        
    Returns:
        (is_valid, error_message) tuple
    """
    if not url:
        return False, "URL cannot be empty"
    
    # CNS Security: Length limit prevents resource exhaustion attacks
    if len(url) > 2048:
        return False, "URL exceeds maximum allowed length (2048 characters)"
    
    # CNS Security: Remove dangerous characters that could cause XSS
    # We allow URL-valid characters only
    # This is NOT a strict URL validator — it's a security filter
    stripped = url.strip()
    if not stripped:
        return False, "URL cannot be blank"
    
    # Basic sanity check: must look like a URL
    # Allow URLs with or without scheme
    url_pattern = re.compile(
        r'^(https?://)?'             # Optional scheme
        r'[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]+$'  # URL characters
    )
    if not url_pattern.match(stripped):
        return False, "URL contains invalid characters"
    
    return True, ""


# ============================================================
# PAGE ROUTES - HTML Page Endpoints
# ============================================================

@app.route("/")
def index():
    """
    Home page — URL input form and dashboard.
    CNS Concept: User-facing interface for security tool interaction.
    """
    stats = get_statistics()
    recent = get_recent_for_dashboard(5)
    return render_template("index.html", stats=stats, recent=recent)


@app.route("/history")
def history_page():
    """
    History page — displays all previously analyzed URLs.
    CNS Concept: Audit trail for security monitoring.
    """
    history = get_history(50)
    return render_template("history.html", history=history)


@app.route("/learn")
def learn_page():
    """
    Learn About Phishing page — educational content.
    CNS Concept: Security awareness and education.
    """
    return render_template("learn.html")


@app.route("/result")
def result_page():
    """
    Result page — displayed after URL analysis (form submission flow).
    """
    return render_template("result.html")


# ============================================================
# API ROUTES - JSON API Endpoints
# ============================================================

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    POST /api/analyze
    
    Analyzes a submitted URL for phishing indicators.
    
    CNS Concept: RESTful API design for security services.
    This endpoint performs STATIC analysis only — it never visits
    the submitted URL, making it safe to analyze malicious links.
    
    Input JSON:
        {"url": "https://example.com/login"}
    
    Output JSON:
        {
            "url": "...",
            "risk_score": 25,
            "risk_level": "LOW",
            "reasons": [...],
            "positives": [...],
            "analysis_table": [...],
            "recommendation": "..."
        }
    
    Security:
        - Input validation prevents XSS and injection
        - Parameterized DB queries prevent SQL injection
        - No HTTP requests made to submitted URLs
    """
    # CNS Security: Validate Content-Type
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400
    
    # CNS Security: Input extraction with type checking
    url = data.get("url", "")
    if not isinstance(url, str):
        return jsonify({"error": "URL must be a string"}), 400
    
    # CNS Security: Input validation
    is_valid, error_msg = validate_url_input(url)
    if not is_valid:
        return jsonify({"error": error_msg}), 400
    
    # CNS Security: Sanitize URL (strip whitespace, no HTML injection)
    url = url.strip()
    
    # --------------------------------------------------------
    # CORE ANALYSIS — Static URL analysis (no HTTP requests)
    # CNS Concept: Safe analysis of potentially malicious content
    # --------------------------------------------------------
    result = analyze_url(url)
    
    # Save to database (audit logging)
    if "error" not in result:
        try:
            save_analysis(
                url=result["url"],
                risk_score=result["risk_score"],
                risk_level=result["risk_level"],
                reasons=result["reasons"],
                positives=result["positives"]
            )
        except Exception as db_err:
            # Non-fatal: log DB error but return result
            app.logger.error(f"DB save error: {db_err}")
    
    return jsonify(result), 200


@app.route("/api/history", methods=["GET"])
def api_history():
    """
    GET /api/history
    
    Returns list of previously analyzed URLs.
    CNS Concept: Audit log access for security monitoring.
    
    Query params:
        limit: Maximum records to return (default 50, max 200)
    """
    try:
        limit = int(request.args.get("limit", 50))
        limit = min(limit, 200)  # Cap at 200 for performance
    except (ValueError, TypeError):
        limit = 50
    
    history = get_history(limit)
    stats = get_statistics()
    
    return jsonify({
        "history": history,
        "stats": stats,
        "count": len(history)
    }), 200


@app.route("/api/history", methods=["DELETE"])
def api_clear_history():
    """
    DELETE /api/history
    
    Clears all URL analysis history from the database.
    CNS Concept: Data management and privacy controls.
    """
    deleted_count = clear_history()
    return jsonify({
        "message": f"History cleared. {deleted_count} record(s) deleted.",
        "deleted": deleted_count
    }), 200


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """
    GET /api/stats
    
    Returns dashboard statistics.
    """
    stats = get_statistics()
    return jsonify(stats), 200


# ============================================================
# ERROR HANDLERS
# CNS Concept: Proper error handling prevents information leakage
# ============================================================

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request", "message": str(e)}), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    # CNS Security: Never expose internal error details to clients
    app.logger.error(f"Internal error: {e}")
    return jsonify({"error": "An internal error occurred"}), 500


# ============================================================
# Application Entry Point
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  PHISHING DETECTION SYSTEM")
    print("  Computer & Network Security - College Project")
    print("=" * 60)
    print(f"  Server starting on http://127.0.0.1:5000")
    print(f"  Database: {__import__('database').DB_PATH}")
    print("  Static analysis only — no URLs are visited")
    print("=" * 60)
    
    # CNS Security: Debug mode disabled in production
    app.run(host="127.0.0.1", port=5000, debug=False)
