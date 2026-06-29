# =============================================================================
# Password Guardian Pro — app.py
# =============================================================================
# Flask application entry point. Defines all REST API routes and serves
# the single-page frontend.
#
# API surface:
#   POST /api/analyze      — Full password analysis report
#   POST /api/generate     — Secure password generation
#   GET  /api/history      — Paginated analysis history
#   GET  /api/stats        — Aggregated dashboard statistics
#   POST /api/clear        — Clear history (dev/demo use)
#   GET  /                 — SPA frontend
# =============================================================================

import os
import logging
import time
from functools import wraps

from flask import Flask, request, jsonify, render_template, abort

from utils.checker   import analyze_password
from utils.generator import generate_password, generate_passphrase, generate_pin
from utils.database  import init_db, save_analysis, get_history, get_stats, clear_history

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """
    Flask application factory.

    Initialises the database, registers all routes, and attaches
    error handlers. Returns a configured Flask app instance.

    Returns:
        Flask: Configured application.
    """
    app = Flask(__name__)

    # --- Security headers middleware ---
    @app.after_request
    def set_security_headers(response):
        """Attach security-relevant HTTP headers to every response."""
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]          = "DENY"
        response.headers["X-XSS-Protection"]         = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"]             = "no-store"
        return response

    # --- Initialise database ---
    with app.app_context():
        init_db()
        logger.info("Password Guardian Pro starting up.")

    # -------------------------------------------------------------------------
    # Frontend
    # -------------------------------------------------------------------------

    @app.route("/")
    def index():
        """Serve the single-page application."""
        return render_template("index.html")

    # -------------------------------------------------------------------------
    # POST /api/analyze
    # -------------------------------------------------------------------------

    @app.route("/api/analyze", methods=["POST"])
    def analyze():
        """
        Analyse a password and return a full security report.

        Request body (JSON):
            { "password": str, "save": bool (optional, default true) }

        Response (JSON):
            Full analysis report from checker.analyze_password(), plus
            a "saved" boolean indicating whether the result was persisted.

        Status codes:
            200 — Success
            400 — Missing or invalid input
            500 — Internal analysis error
        """
        data = _parse_json_body()
        if data is None:
            return _error("Request body must be valid JSON.", 400)

        password = data.get("password", "")
        save     = data.get("save", True)

        # --- Input validation ---
        if not isinstance(password, str):
            return _error("'password' must be a string.", 400)
        if len(password) == 0:
            return _error("Password cannot be empty.", 400)
        if len(password) > 512:
            return _error("Password exceeds maximum length of 512 characters.", 400)

        # --- Analysis ---
        try:
            start  = time.perf_counter()
            report = analyze_password(password)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        except Exception as exc:
            logger.exception("Analysis failed: %s", exc)
            return _error("Analysis failed. Please try again.", 500)

        # --- Persist (never stores raw password) ---
        saved    = False
        saved_id = None
        if save:
            try:
                saved_id = save_analysis(report)
                saved    = True
            except Exception as exc:
                logger.warning("Failed to save analysis: %s", exc)

        report["saved"]      = saved
        report["saved_id"]   = saved_id
        report["elapsed_ms"] = elapsed_ms

        logger.info("Analyzed password — score=%d strength=%s elapsed=%sms",
                    report["score"], report["strength"], elapsed_ms)

        return jsonify(report), 200

    # -------------------------------------------------------------------------
    # POST /api/generate
    # -------------------------------------------------------------------------

    @app.route("/api/generate", methods=["POST"])
    def generate():
        """
        Generate a cryptographically secure password.

        Request body (JSON):
            {
                "mode":             str  ("random" | "passphrase" | "pin"),
                "length":           int  (8–128, default 16),
                "use_uppercase":    bool (default true),
                "use_lowercase":    bool (default true),
                "use_digits":       bool (default true),
                "use_symbols":      bool (default true),
                "avoid_ambiguous":  bool (default false),
                "pronounceable":    bool (default false),
                "word_count":       int  (3–10, passphrase mode only),
                "separator":        str  (passphrase mode only),
            }

        Response (JSON):
            Generator result dict (password/passphrase/pin + metadata).

        Status codes:
            200 — Success
            400 — Invalid input
            500 — Generation error
        """
        data = _parse_json_body() or {}

        mode = data.get("mode", "random")

        try:
            if mode == "passphrase":
                result = generate_passphrase(
                    word_count    = int(data.get("word_count", 4)),
                    separator     = str(data.get("separator", "-"))[:3],
                    capitalise    = bool(data.get("capitalise", True)),
                    append_number = bool(data.get("append_number", True)),
                )

            elif mode == "pin":
                result = generate_pin(
                    length = int(data.get("length", 6))
                )

            else:  # default: random
                result = generate_password(
                    length          = int(data.get("length",          16)),
                    use_uppercase   = bool(data.get("use_uppercase",   True)),
                    use_lowercase   = bool(data.get("use_lowercase",   True)),
                    use_digits      = bool(data.get("use_digits",      True)),
                    use_symbols     = bool(data.get("use_symbols",     True)),
                    avoid_ambiguous = bool(data.get("avoid_ambiguous", False)),
                    pronounceable   = bool(data.get("pronounceable",   False)),
                )

        except ValueError as exc:
            return _error(str(exc), 400)
        except Exception as exc:
            logger.exception("Generation failed: %s", exc)
            return _error("Generation failed. Please try again.", 500)

        result["mode"] = mode
        logger.info("Generated %s — length=%s", mode, result.get("length", "N/A"))
        return jsonify(result), 200

    # -------------------------------------------------------------------------
    # GET /api/history
    # -------------------------------------------------------------------------

    @app.route("/api/history", methods=["GET"])
    def history():
        """
        Return paginated password analysis history.

        Query parameters:
            limit  (int): Records per page. Default 20, max 100.
            offset (int): Pagination offset. Default 0.

        Response (JSON):
            {
                "records": list[dict],
                "count":   int,
                "limit":   int,
                "offset":  int,
            }

        Status codes:
            200 — Success
            500 — Database error
        """
        try:
            limit  = int(request.args.get("limit",  20))
            offset = int(request.args.get("offset",  0))
        except (ValueError, TypeError):
            return _error("'limit' and 'offset' must be integers.", 400)

        try:
            records = get_history(limit=limit, offset=offset)
        except Exception as exc:
            logger.exception("Failed to fetch history: %s", exc)
            return _error("Could not retrieve history.", 500)

        return jsonify({
            "records": records,
            "count":   len(records),
            "limit":   limit,
            "offset":  offset,
        }), 200

    # -------------------------------------------------------------------------
    # GET /api/stats
    # -------------------------------------------------------------------------

    @app.route("/api/stats", methods=["GET"])
    def stats():
        """
        Return aggregated dashboard statistics.

        Response (JSON):
            Stats dict from database.get_stats().

        Status codes:
            200 — Success
            500 — Database error
        """
        try:
            data = get_stats()
        except Exception as exc:
            logger.exception("Failed to fetch stats: %s", exc)
            return _error("Could not retrieve statistics.", 500)

        return jsonify(data), 200

    # -------------------------------------------------------------------------
    # POST /api/clear
    # -------------------------------------------------------------------------

    @app.route("/api/clear", methods=["POST"])
    def clear():
        """
        Clear all stored analysis history and reset statistics.

        Intended for demo/development use. In production this route
        should be protected by authentication middleware.

        Response (JSON):
            { "deleted": int, "message": str }

        Status codes:
            200 — Success
            500 — Database error
        """
        try:
            deleted = clear_history()
        except Exception as exc:
            logger.exception("Failed to clear history: %s", exc)
            return _error("Could not clear history.", 500)

        logger.info("History cleared — %d records deleted.", deleted)
        return jsonify({
            "deleted": deleted,
            "message": f"Successfully deleted {deleted} records.",
        }), 200

    # -------------------------------------------------------------------------
    # Error handlers
    # -------------------------------------------------------------------------

    @app.errorhandler(404)
    def not_found(e):
        return _error("Endpoint not found.", 404)

    @app.errorhandler(405)
    def method_not_allowed(e):
        return _error("Method not allowed.", 405)

    @app.errorhandler(500)
    def internal_error(e):
        return _error("Internal server error.", 500)

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_json_body() -> dict | None:
    """
    Safely parse the JSON request body.

    Returns None if the body is missing, malformed, or not JSON.

    Returns:
        dict | None: Parsed JSON body or None on failure.
    """
    try:
        return request.get_json(force=True, silent=True)
    except Exception:
        return None


def _error(message: str, status: int) -> tuple:
    """
    Build a consistent JSON error response.

    Args:
        message (str): Human-readable error description.
        status  (int): HTTP status code.

    Returns:
        tuple: (flask.Response, int)
    """
    return jsonify({"error": message, "status": status}), status


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

app = create_app()

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    port       = int(os.environ.get("PORT", 5000))

    logger.info("Starting Password Guardian Pro on port %d (debug=%s)",
                port, debug_mode)

    app.run(
        host  = "0.0.0.0",
        port  = port,
        debug = debug_mode,
    )

