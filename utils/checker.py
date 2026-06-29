# =============================================================================
# Password Guardian Pro — utils/checker.py
# =============================================================================
# Core password analysis engine. Orchestrates all checks and returns a
# structured report consumed by the Flask API and rendered on the frontend.
# =============================================================================

import re
import math
import hashlib
import logging
import os
from zxcvbn import zxcvbn

from utils.entropy import (
    calculate_entropy,
    calculate_true_entropy,
    estimate_crack_time,
    entropy_to_grade,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_COMMON_PASSWORDS_PATH = os.path.join(_BASE_DIR, "datasets", "common_passwords.txt")

# ---------------------------------------------------------------------------
# Common password dataset (loaded once at import time)
# ---------------------------------------------------------------------------

def _load_common_passwords() -> set:
    """
    Load the common passwords dataset into a set for O(1) lookups.

    Returns:
        set: Lowercase common passwords.
    """
    try:
        with open(_COMMON_PASSWORDS_PATH, "r", encoding="utf-8") as f:
            passwords = {line.strip().lower() for line in f if line.strip()}
        logger.info("Loaded %d common passwords from dataset.", len(passwords))
        return passwords
    except FileNotFoundError:
        logger.warning("Common passwords dataset not found at %s", _COMMON_PASSWORDS_PATH)
        return set()
    except Exception as exc:
        logger.error("Failed to load common passwords: %s", exc)
        return set()


COMMON_PASSWORDS: set = _load_common_passwords()

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

# Each criterion contributes a maximum number of points toward a 100-point score.
SCORING_WEIGHTS = {
    "length":           25,   # Most impactful — length dominates entropy
    "uppercase":         8,
    "lowercase":         8,
    "digits":            8,
    "symbols":          12,
    "entropy":          20,   # Raw information-theoretic strength
    "no_common":        10,   # Not in breach/common list
    "no_repeats":        5,
    "no_sequences":      4,
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_password(password: str) -> dict:
    """
    Run a full security analysis on the given password.

    Orchestrates all sub-checks, aggregates scores, and returns a single
    structured report dictionary safe to serialise as JSON.

    Args:
        password (str): The plaintext password to analyse.

    Returns:
        dict: Full analysis report. Structure:
            {
                "score":          int   (0–100),
                "strength":       str,
                "grade":          str,
                "color":          str,
                "entropy":        float,
                "true_entropy":   float,
                "crack_time":     dict,
                "checks":         dict,
                "suggestions":    list[str],
                "breached":       bool,
                "hash":           str   (SHA-256 hex digest),
                "length":         int,
                "zxcvbn_score":   int   (0–4),
                "zxcvbn_feedback": dict,
            }
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    # --- Core checks ---
    checks      = _run_checks(password)
    score       = _calculate_score(password, checks)
    entropy     = calculate_entropy(password)
    true_entropy = calculate_true_entropy(password)
    crack_time  = estimate_crack_time(true_entropy)
    grade_info  = entropy_to_grade(true_entropy)
    suggestions = _generate_suggestions(password, checks)
    breached    = _is_common_password(password)
    pw_hash     = _sha256(password)

    # --- zxcvbn cross-check ---
    zx          = _run_zxcvbn(password)

    # Blend our score with zxcvbn result for a more robust final score
    blended_score = _blend_scores(score, zx["score"])

    # Override grade/strength if breached
    if breached:
        suggestions.insert(0, "⚠ This password has appeared in previous data breaches.")
        blended_score = min(blended_score, 15)

    strength = _score_to_strength(blended_score)

    report = {
        "score":            blended_score,
        "strength":         strength,
        "grade":            grade_info["grade"],
        "color":            grade_info["color"],
        "entropy":          entropy,
        "true_entropy":     true_entropy,
        "crack_time":       crack_time,
        "checks":           checks,
        "suggestions":      suggestions,
        "breached":         breached,
        "hash":             pw_hash,
        "length":           len(password),
        "zxcvbn_score":     zx["score"],
        "zxcvbn_feedback":  zx["feedback"],
    }

    logger.debug("Analysis complete — score=%d strength=%s entropy=%.2f",
                 blended_score, strength, true_entropy)
    return report


def get_password_hash(password: str) -> str:
    """
    Return the SHA-256 hex digest of a password.
    Used externally by database.py to store analyses without raw passwords.

    Args:
        password (str): Plaintext password.

    Returns:
        str: 64-character hex digest.
    """
    return _sha256(password)


# ---------------------------------------------------------------------------
# Check runners
# ---------------------------------------------------------------------------

def _run_checks(password: str) -> dict:
    """
    Execute all individual password checks.

    Args:
        password (str): Input password.

    Returns:
        dict: Boolean/value results for every criterion.
    """
    return {
        # Boolean checks
        "has_uppercase":        bool(re.search(r'[A-Z]', password)),
        "has_lowercase":        bool(re.search(r'[a-z]', password)),
        "has_digits":           bool(re.search(r'[0-9]', password)),
        "has_symbols":          bool(re.search(r'[!-/:-@\[-`{-~]', password)),
        "has_space":            ' ' in password,

        # Length bands
        "length":               len(password),
        "length_ok":            len(password) >= 8,
        "length_good":          len(password) >= 12,
        "length_strong":        len(password) >= 16,
        "length_excellent":     len(password) >= 20,

        # Pattern checks (True = problem detected)
        "has_repeats":          _has_repeated_chars(password),
        "has_sequences":        _has_sequential_chars(password),
        "has_keyboard_walk":    _has_keyboard_walk(password),
        "has_leet_speak":       _has_leet_speak(password),
        "has_common_words":     _has_common_words(password),
        "starts_with_upper":    password[0].isupper() if password else False,
        "ends_with_digit":      password[-1].isdigit() if password else False,

        # Character class counts
        "uppercase_count":      len(re.findall(r'[A-Z]', password)),
        "lowercase_count":      len(re.findall(r'[a-z]', password)),
        "digit_count":          len(re.findall(r'[0-9]', password)),
        "symbol_count":         len(re.findall(r'[!-/:-@\[-`{-~]', password)),
        "unique_chars":         len(set(password)),
        "unique_ratio":         round(len(set(password)) / len(password), 2) if password else 0,
    }


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

def _calculate_score(password: str, checks: dict) -> int:
    """
    Compute a 0–100 security score from check results.

    Args:
        password (str): Input password.
        checks (dict): Output of _run_checks().

    Returns:
        int: Score clamped to [0, 100].
    """
    score = 0

    # --- Length (25 pts) ---
    length = checks["length"]
    if length >= 20:
        score += 25
    elif length >= 16:
        score += 20
    elif length >= 12:
        score += 15
    elif length >= 8:
        score += 8
    elif length >= 6:
        score += 3

    # --- Character classes (8+8+8+12 = 36 pts) ---
    if checks["has_uppercase"]:
        score += 8
    if checks["has_lowercase"]:
        score += 8
    if checks["has_digits"]:
        score += 8
    if checks["has_symbols"]:
        score += 12

    # --- Entropy (20 pts) ---
    entropy = calculate_entropy(password)
    if entropy >= 100:
        score += 20
    elif entropy >= 80:
        score += 17
    elif entropy >= 60:
        score += 13
    elif entropy >= 40:
        score += 8
    elif entropy >= 20:
        score += 3

    # --- Not a common password (10 pts) ---
    if not _is_common_password(password):
        score += 10

    # --- No repeated chars (5 pts) ---
    if not checks["has_repeats"]:
        score += 5

    # --- No sequences (4 pts) ---
    if not checks["has_sequences"]:
        score += 4

    # --- Penalties ---
    if checks["has_keyboard_walk"]:
        score -= 10
    if checks["ends_with_digit"] and not checks["has_symbols"]:
        # Common lazy pattern: Password1
        score -= 5
    if checks["starts_with_upper"] and checks["ends_with_digit"]:
        # Classic weak pattern capitalisation
        score -= 3
    if checks["unique_ratio"] < 0.5:
        score -= 5

    return max(0, min(100, score))


def _blend_scores(our_score: int, zxcvbn_raw: int) -> int:
    """
    Blend our heuristic score with zxcvbn's 0-4 scale.

    Converts zxcvbn's scale to 0-100 and weights:
        70% our engine + 30% zxcvbn

    Args:
        our_score (int): Our 0–100 score.
        zxcvbn_raw (int): zxcvbn 0–4 score.

    Returns:
        int: Blended 0–100 score.
    """
    zx_normalised = (zxcvbn_raw / 4) * 100
    blended = int(0.7 * our_score + 0.3 * zx_normalised)
    return max(0, min(100, blended))


# ---------------------------------------------------------------------------
# Suggestion engine
# ---------------------------------------------------------------------------

def _generate_suggestions(password: str, checks: dict) -> list:
    """
    Generate prioritised, actionable improvement suggestions.

    Returns the most impactful suggestions first (length, then diversity,
    then patterns).

    Args:
        password (str): Input password.
        checks (dict): Output of _run_checks().

    Returns:
        list[str]: Ordered list of human-readable suggestion strings.
    """
    suggestions = []

    # --- Length ---
    if checks["length"] < 8:
        suggestions.append("🔴 Password is too short — use at least 12 characters.")
    elif checks["length"] < 12:
        suggestions.append("🟠 Increase length to at least 12 characters for better security.")
    elif checks["length"] < 16:
        suggestions.append("🟡 Consider using 16+ characters for a strong password.")

    # --- Character classes ---
    if not checks["has_uppercase"]:
        suggestions.append("🔠 Add uppercase letters (A–Z) to expand the character pool.")
    if not checks["has_lowercase"]:
        suggestions.append("🔡 Add lowercase letters (a–z).")
    if not checks["has_digits"]:
        suggestions.append("🔢 Include at least one number (0–9).")
    if not checks["has_symbols"]:
        suggestions.append("🔣 Add symbols (!@#$%^&*) — they dramatically increase entropy.")

    # --- Patterns ---
    if checks["has_repeats"]:
        suggestions.append("🔁 Avoid repeated characters (e.g., 'aaa', '111').")
    if checks["has_sequences"]:
        suggestions.append("🔢 Avoid sequential characters (e.g., 'abc', '123', 'xyz').")
    if checks["has_keyboard_walk"]:
        suggestions.append("⌨️  Avoid keyboard patterns (e.g., 'qwerty', 'asdf', 'zxcv').")
    if checks["has_leet_speak"]:
        suggestions.append("🔤 Simple leet-speak substitutions (@ for a, 3 for e) are well-known to attackers.")
    if checks["has_common_words"]:
        suggestions.append("📖 Contains common dictionary words — try combining random unrelated words.")

    # --- Structural red flags ---
    if checks["starts_with_upper"] and checks["ends_with_digit"]:
        suggestions.append("⚠️  'Capital letter + word + number' is the most predictable pattern — avoid it.")
    if checks["unique_ratio"] < 0.5:
        suggestions.append("🔄 Too many repeated characters — aim for more unique characters.")

    # --- Positive reinforcement (no suggestions = good) ---
    if not suggestions:
        suggestions.append("✅ Excellent password! No obvious weaknesses detected.")

    return suggestions


# ---------------------------------------------------------------------------
# Individual pattern detectors
# ---------------------------------------------------------------------------

def _has_repeated_chars(password: str) -> bool:
    """
    Detect 3+ consecutive identical characters.

    Args:
        password (str): Input password.

    Returns:
        bool: True if repeated chars found.
    """
    return bool(re.search(r'(.)\1{2,}', password))


def _has_sequential_chars(password: str) -> bool:
    """
    Detect runs of 3+ sequential ascending or descending characters.

    Checks both alphabetical (abc, zyx) and numeric (123, 987) sequences.

    Args:
        password (str): Input password.

    Returns:
        bool: True if sequential run found.
    """
    for i in range(len(password) - 2):
        a, b, c = ord(password[i]), ord(password[i+1]), ord(password[i+2])
        if (b - a == 1 and c - b == 1) or (a - b == 1 and b - c == 1):
            return True
    return False


def _has_keyboard_walk(password: str) -> bool:
    """
    Detect known keyboard row/walk patterns of 4+ characters.

    Args:
        password (str): Input password.

    Returns:
        bool: True if keyboard walk detected.
    """
    keyboard_sequences = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890", "!@#$%^&*()",
        "qwerty", "asdf", "zxcv", "wasd",
    ]
    pw_lower = password.lower()
    for seq in keyboard_sequences:
        for length in range(4, len(seq) + 1):
            for start in range(len(seq) - length + 1):
                chunk = seq[start:start + length]
                if chunk in pw_lower or chunk[::-1] in pw_lower:
                    return True
    return False


def _has_leet_speak(password: str) -> bool:
    """
    Detect simple leet-speak substitutions that attackers account for.

    Common mappings: @ → a, 3 → e, 1 → i/l, 0 → o, 5 → s, 7 → t

    Args:
        password (str): Input password.

    Returns:
        bool: True if leet-speak substitution pattern detected.
    """
    leet_map = str.maketrans("@31057", "aeiost")
    normalised = password.translate(leet_map).lower()

    common_words = [
        "password", "passw0rd", "admin", "login", "welcome",
        "dragon", "master", "hello", "monkey", "shadow",
    ]
    return any(word in normalised for word in common_words)


def _has_common_words(password: str) -> bool:
    """
    Detect the presence of common dictionary words (4+ letters) in the password.

    Args:
        password (str): Input password.

    Returns:
        bool: True if a common word is found.
    """
    common_words = [
        "password", "admin", "login", "user", "welcome", "hello",
        "dragon", "master", "monkey", "shadow", "sunshine", "princess",
        "football", "baseball", "soccer", "batman", "superman",
        "computer", "internet", "security", "michael", "jennifer",
        "thomas", "jordan", "hunter", "ranger", "summer", "winter",
        "spring", "autumn", "monday", "friday", "january", "december",
    ]
    pw_lower = password.lower()
    return any(word in pw_lower for word in common_words)


def _is_common_password(password: str) -> bool:
    """
    Check if the password exists in the common/breached password dataset.

    Args:
        password (str): Input password.

    Returns:
        bool: True if found in the dataset.
    """
    return password.lower() in COMMON_PASSWORDS


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _sha256(password: str) -> str:
    """
    Compute the SHA-256 hex digest of a password string.

    Args:
        password (str): Plaintext password.

    Returns:
        str: 64-character lowercase hex string.
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _run_zxcvbn(password: str) -> dict:
    """
    Run the zxcvbn library and return a safe, serialisable subset of its output.

    zxcvbn provides pattern-based analysis (dates, names, keyboard walks)
    that complements our heuristic engine.

    Args:
        password (str): Input password.

    Returns:
        dict: { "score": int, "feedback": dict }
    """
    try:
        result = zxcvbn(password)
        return {
            "score":    result.get("score", 0),
            "feedback": result.get("feedback", {"suggestions": [], "warning": ""}),
        }
    except Exception as exc:
        logger.error("zxcvbn analysis failed: %s", exc)
        return {"score": 0, "feedback": {"suggestions": [], "warning": ""}}


def _score_to_strength(score: int) -> str:
    """
    Convert a 0–100 numeric score to a strength label.

    Args:
        score (int): Blended security score.

    Returns:
        str: One of "Very Weak", "Weak", "Fair", "Strong", "Very Strong".
    """
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 80:
        return "Strong"
    return "Very Strong"
