# =============================================================================
# Password Guardian Pro — utils/entropy.py
# =============================================================================
# Handles all entropy-related calculations for password strength analysis.
# Entropy is measured in bits; higher = harder to crack via brute force.
# =============================================================================

import math
import re
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Character pool size constants
# ---------------------------------------------------------------------------

POOL_LOWERCASE   = 26      # a-z
POOL_UPPERCASE   = 26      # A-Z
POOL_DIGITS      = 10      # 0-9
POOL_SYMBOLS     = 32      # standard keyboard symbols
POOL_SPACE       = 1       # space character
POOL_EXTENDED    = 128     # extended ASCII (uncommon but valid)


# ---------------------------------------------------------------------------
# Brute-force speed assumptions (guesses per second)
# Used for crack-time estimation under different attack scenarios.
# ---------------------------------------------------------------------------

ATTACK_SCENARIOS = {
    "online_throttled":    100,           # Rate-limited online login (100/s)
    "online_unthrottled":  10_000,        # No rate-limit online attack
    "offline_slow":        1_000_000,     # Bcrypt / scrypt offline
    "offline_fast":        100_000_000,   # MD5 / SHA1 GPU offline
    "offline_gpu_cluster": 100_000_000_000,  # Nation-state GPU cluster
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_entropy(password: str) -> float:
    """
    Calculate Shannon entropy for a password based on its character pool size.

    Formula:
        H = L * log2(R)
    Where:
        H = entropy in bits
        L = password length
        R = size of the character pool used

    Args:
        password (str): The password to evaluate.

    Returns:
        float: Entropy score in bits, rounded to 2 decimal places.
    """
    if not password:
        return 0.0

    pool_size = _get_pool_size(password)

    if pool_size < 2:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    logger.debug("Entropy calculated: %.2f bits (length=%d, pool=%d)",
                 entropy, len(password), pool_size)
    return round(entropy, 2)


def estimate_crack_time(entropy: float) -> dict:
    """
    Estimate crack time across multiple attack scenarios based on entropy.

    Uses the formula:
        combinations = 2 ^ entropy
        time_seconds = combinations / (2 * guesses_per_second)
        (divide by 2 for average-case: attacker finds on average halfway through)

    Args:
        entropy (float): Password entropy in bits.

    Returns:
        dict: {
            "scenario_name": "human_readable_time",
            ...
            "dominant_scenario": "offline_fast",
            "summary": "3 months"
        }
    """
    if entropy <= 0:
        return _build_crack_result({s: "Instant" for s in ATTACK_SCENARIOS},
                                   "Instant")

    combinations = 2 ** entropy
    results = {}

    for scenario, guesses_per_sec in ATTACK_SCENARIOS.items():
        # Average case: attacker succeeds halfway through keyspace
        seconds = combinations / (2 * guesses_per_sec)
        results[scenario] = _seconds_to_human(seconds)

    # The "headline" crack time uses offline_fast (most realistic modern threat)
    summary = results["offline_fast"]

    logger.debug("Crack time (offline_fast): %s for entropy=%.2f bits",
                 summary, entropy)

    return _build_crack_result(results, summary)


def entropy_to_grade(entropy: float) -> dict:
    """
    Convert raw entropy bits into a qualitative strength label and letter grade.

    Thresholds (industry-standard):
        < 28 bits  → Very Weak  (F)
        28–35 bits → Weak       (D)
        36–59 bits → Fair       (C)
        60–79 bits → Strong     (B)
        80–99 bits → Very Strong(A)
        100+ bits  → Excellent  (A+)

    Args:
        entropy (float): Entropy in bits.

    Returns:
        dict: { "label": str, "grade": str, "color": str }
    """
    thresholds = [
        (28,  "Very Weak",   "F",  "#ef4444"),   # red-500
        (36,  "Weak",        "D",  "#f97316"),   # orange-500
        (60,  "Fair",        "C",  "#eab308"),   # yellow-500
        (80,  "Strong",      "B",  "#22c55e"),   # green-500
        (100, "Very Strong", "A",  "#10b981"),   # emerald-500
    ]

    for threshold, label, grade, color in thresholds:
        if entropy < threshold:
            return {"label": label, "grade": grade, "color": color}

    return {"label": "Excellent", "grade": "A+", "color": "#06b6d4"}  # cyan-500


def calculate_true_entropy(password: str) -> float:
    """
    Calculate a penalised entropy that accounts for predictable patterns.

    Applies penalties for:
        - Repeated characters    (reduces effective keyspace)
        - Sequential runs        (predictable structure)
        - Keyboard walk patterns (qwerty, asdf, etc.)

    Args:
        password (str): The password to evaluate.

    Returns:
        float: Adjusted entropy in bits.
    """
    base = calculate_entropy(password)

    penalty = 0.0
    penalty += _repeated_char_penalty(password)
    penalty += _sequential_run_penalty(password)
    penalty += _keyboard_walk_penalty(password)

    true_entropy = max(0.0, base - penalty)
    logger.debug("True entropy: %.2f bits (base=%.2f, penalty=%.2f)",
                 true_entropy, base, penalty)
    return round(true_entropy, 2)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_pool_size(password: str) -> int:
    """
    Determine the character pool size from the character classes present.

    Args:
        password (str): Input password.

    Returns:
        int: Total pool size.
    """
    pool = 0
    if re.search(r'[a-z]', password):
        pool += POOL_LOWERCASE
    if re.search(r'[A-Z]', password):
        pool += POOL_UPPERCASE
    if re.search(r'[0-9]', password):
        pool += POOL_DIGITS
    if re.search(r'[!-/:-@\[-`{-~]', password):
        pool += POOL_SYMBOLS
    if ' ' in password:
        pool += POOL_SPACE
    if any(ord(c) > 127 for c in password):
        pool += POOL_EXTENDED
    return max(pool, 1)


def _seconds_to_human(seconds: float) -> str:
    """
    Convert a raw seconds value into a human-readable duration string.

    Args:
        seconds (float): Number of seconds.

    Returns:
        str: Human-readable string (e.g., "3 months", "Millions of years").
    """
    if seconds < 1:
        return "Instant"
    if seconds < 60:
        return f"{int(seconds)} second{'s' if seconds != 1 else ''}"
    if seconds < 3_600:
        m = int(seconds / 60)
        return f"{m} minute{'s' if m != 1 else ''}"
    if seconds < 86_400:
        h = int(seconds / 3_600)
        return f"{h} hour{'s' if h != 1 else ''}"
    if seconds < 2_592_000:          # 30 days
        d = int(seconds / 86_400)
        return f"{d} day{'s' if d != 1 else ''}"
    if seconds < 31_536_000:         # 365 days
        mo = int(seconds / 2_592_000)
        return f"{mo} month{'s' if mo != 1 else ''}"
    if seconds < 3_153_600_000:      # 100 years
        y = int(seconds / 31_536_000)
        return f"{y} year{'s' if y != 1 else ''}"
    if seconds < 3.154e13:           # 1 million years
        centuries = int(seconds / 3_153_600_000)
        return f"{centuries} centur{'ies' if centuries != 1 else 'y'}"

    return "Millions of years"


def _repeated_char_penalty(password: str) -> float:
    """
    Calculate entropy penalty for repeated characters.

    A password like 'aaaaaaa' has near-zero real entropy despite its length.

    Args:
        password (str): Input password.

    Returns:
        float: Entropy bits to deduct.
    """
    if not password:
        return 0.0

    penalty = 0.0
    freq = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1

    for count in freq.values():
        if count > 1:
            # Each repeated occurrence reduces effective bits
            penalty += (count - 1) * 1.5

    return penalty


def _sequential_run_penalty(password: str) -> float:
    """
    Calculate entropy penalty for sequential character runs.

    Detects alphabetical sequences (abc, xyz) and numeric sequences (123, 987).

    Args:
        password (str): Input password.

    Returns:
        float: Entropy bits to deduct.
    """
    penalty = 0.0
    run_length = 1

    for i in range(1, len(password)):
        diff = ord(password[i]) - ord(password[i - 1])
        if diff in (1, -1):   # ascending or descending by 1
            run_length += 1
            if run_length >= 3:
                penalty += 2.0   # penalise each step beyond 2
        else:
            run_length = 1

    return penalty


def _keyboard_walk_penalty(password: str) -> float:
    """
    Calculate entropy penalty for common keyboard walk patterns.

    Checks against known horizontal rows and vertical columns.

    Args:
        password (str): Input password.

    Returns:
        float: Entropy bits to deduct.
    """
    keyboard_rows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
        "!@#$%^&*()",
    ]

    penalty = 0.0
    pw_lower = password.lower()

    for row in keyboard_rows:
        for length in range(4, len(password) + 1):
            for start in range(len(row) - length + 1):
                substr = row[start:start + length]
                if substr in pw_lower or substr[::-1] in pw_lower:
                    penalty += length * 1.5

    return penalty


def _build_crack_result(scenario_times: dict, summary: str) -> dict:
    """
    Assemble the final crack time result dictionary.

    Args:
        scenario_times (dict): Per-scenario human-readable times.
        summary (str): Headline crack time.

    Returns:
        dict: Structured crack time result.
    """
    return {
        "online_throttled":    scenario_times.get("online_throttled", "N/A"),
        "online_unthrottled":  scenario_times.get("online_unthrottled", "N/A"),
        "offline_slow":        scenario_times.get("offline_slow", "N/A"),
        "offline_fast":        scenario_times.get("offline_fast", "N/A"),
        "offline_gpu_cluster": scenario_times.get("offline_gpu_cluster", "N/A"),
        "summary":             summary,
    }
