# =============================================================================
# Password Guardian Pro — utils/generator.py
# =============================================================================
# Cryptographically secure password generator using Python's `secrets` module.
#
# Why `secrets` and not `random`?
#   - `random` uses a Mersenne Twister PRNG — predictable if seeded state leaks.
#   - `secrets` uses the OS CSPRNG (/dev/urandom on Linux, CryptGenRandom on Windows).
#   - For security tooling, there is no acceptable reason to use `random`.
# =============================================================================

import secrets
import string
import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Character pool definitions
# ---------------------------------------------------------------------------

POOL_LOWERCASE  = string.ascii_lowercase          # a-z
POOL_UPPERCASE  = string.ascii_uppercase          # A-Z
POOL_DIGITS     = string.digits                   # 0-9
POOL_SYMBOLS    = "!@#$%^&*()-_=+[]{}|;:,.<>?"   # Curated — excludes backtick,
                                                  # quote chars that break CLIs

# Ambiguous characters that look similar in many fonts
# (excluded in "avoid ambiguous" mode)
AMBIGUOUS_CHARS = set("0O1lIiS5B8")

# Pronounceable mode: consonant/vowel pools for readable syllables
VOWELS     = "aeiou"
CONSONANTS = "bcdfghjklmnpqrstvwxyz"

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_password(
    length:            int  = 16,
    use_uppercase:     bool = True,
    use_lowercase:     bool = True,
    use_digits:        bool = True,
    use_symbols:       bool = True,
    avoid_ambiguous:   bool = False,
    pronounceable:     bool = False,
) -> dict:
    """
    Generate a cryptographically secure password with configurable options.

    At least one character class must be enabled. If `pronounceable` is True,
    the password is built from alternating consonant/vowel syllables and then
    hardened by injecting mandatory character classes.

    Args:
        length          (int):  Desired password length. Clamped to [8, 128].
        use_uppercase   (bool): Include A-Z.
        use_lowercase   (bool): Include a-z.
        use_digits      (bool): Include 0-9.
        use_symbols     (bool): Include symbols.
        avoid_ambiguous (bool): Exclude visually similar characters (0, O, 1, l…).
        pronounceable   (bool): Generate a human-readable syllabic password.

    Returns:
        dict: {
            "password":    str,
            "length":      int,
            "entropy":     float,
            "pool_size":   int,
            "options":     dict,   # echo of settings used
        }

    Raises:
        ValueError: If no character class is selected or length is invalid.
    """
    # --- Input validation ---
    length = _clamp(length, 8, 128)

    if not any([use_uppercase, use_lowercase, use_digits, use_symbols]):
        raise ValueError("At least one character class must be enabled.")

    options = {
        "length":          length,
        "use_uppercase":   use_uppercase,
        "use_lowercase":   use_lowercase,
        "use_digits":      use_digits,
        "use_symbols":     use_symbols,
        "avoid_ambiguous": avoid_ambiguous,
        "pronounceable":   pronounceable,
    }

    if pronounceable:
        password = _generate_pronounceable(
            length, use_uppercase, use_digits, use_symbols, avoid_ambiguous
        )
    else:
        password = _generate_random(
            length, use_uppercase, use_lowercase,
            use_digits, use_symbols, avoid_ambiguous
        )

    pool_size  = _compute_pool_size(use_uppercase, use_lowercase,
                                    use_digits, use_symbols, avoid_ambiguous)
    entropy    = _compute_entropy(len(password), pool_size)

    logger.debug("Generated password — length=%d pool=%d entropy=%.2f bits",
                 len(password), pool_size, entropy)

    return {
        "password":  password,
        "length":    len(password),
        "entropy":   round(entropy, 2),
        "pool_size": pool_size,
        "options":   options,
    }


def generate_passphrase(
    word_count:    int  = 4,
    separator:     str  = "-",
    capitalise:    bool = True,
    append_number: bool = True,
) -> dict:
    """
    Generate a Diceware-style passphrase from a built-in word list.

    Passphrases trade character complexity for length, which achieves strong
    entropy while remaining memorable. A 4-word passphrase with numbers
    typically yields ~50–60 bits of entropy.

    Args:
        word_count    (int): Number of words. Clamped to [3, 10].
        separator     (str): Character between words (default "-").
        capitalise    (bool): Capitalise first letter of each word.
        append_number (bool): Append a random 2-digit number to the last word.

    Returns:
        dict: {
            "passphrase": str,
            "word_count": int,
            "entropy":    float,
        }
    """
    word_count = _clamp(word_count, 3, 10)

    words = [secrets.choice(_WORD_LIST) for _ in range(word_count)]

    if capitalise:
        words = [w.capitalize() for w in words]

    if append_number:
        words[-1] += str(secrets.randbelow(90) + 10)  # 10–99

    passphrase = separator.join(words)
    entropy    = _compute_entropy(len(passphrase), 26 + 10)  # approx

    logger.debug("Generated passphrase — words=%d entropy=%.2f", word_count, entropy)

    return {
        "passphrase": passphrase,
        "word_count": word_count,
        "entropy":    round(entropy, 2),
    }


def generate_pin(length: int = 6) -> dict:
    """
    Generate a cryptographically secure numeric PIN.

    Args:
        length (int): PIN length. Clamped to [4, 12].

    Returns:
        dict: { "pin": str, "length": int, "entropy": float }
    """
    length = _clamp(length, 4, 12)
    pin    = "".join(str(secrets.randbelow(10)) for _ in range(length))
    entropy = _compute_entropy(length, 10)

    return {
        "pin":     pin,
        "length":  length,
        "entropy": round(entropy, 2),
    }


# ---------------------------------------------------------------------------
# Core generation engines
# ---------------------------------------------------------------------------

def _generate_random(
    length:          int,
    use_uppercase:   bool,
    use_lowercase:   bool,
    use_digits:      bool,
    use_symbols:     bool,
    avoid_ambiguous: bool,
) -> str:
    """
    Generate a truly random password using secrets.choice().

    Guarantees at least one character from every enabled class by
    injecting mandatory characters before filling the remainder,
    then shuffling the whole string with a Fisher-Yates via secrets.

    Args:
        (see generate_password)

    Returns:
        str: Generated password.
    """
    pool      = _build_pool(use_uppercase, use_lowercase,
                            use_digits, use_symbols, avoid_ambiguous)
    mandatory = _get_mandatory_chars(use_uppercase, use_lowercase,
                                     use_digits, use_symbols, avoid_ambiguous)

    if len(mandatory) > length:
        # More classes than length — truncate mandatory set
        mandatory = mandatory[:length]

    # Fill remaining slots from full pool
    remaining = length - len(mandatory)
    filler    = [secrets.choice(pool) for _ in range(remaining)]

    # Combine and shuffle securely
    password_chars = mandatory + filler
    _secure_shuffle(password_chars)

    return "".join(password_chars)


def _generate_pronounceable(
    length:          int,
    use_uppercase:   bool,
    use_digits:      bool,
    use_symbols:     bool,
    avoid_ambiguous: bool,
) -> str:
    """
    Generate a human-pronounceable password using consonant-vowel syllables.

    Structure: CV CV CV … (consonant-vowel pairs) until target length,
    then inject mandatory digits/symbols at random positions.

    Args:
        length          (int):  Target length.
        use_uppercase   (bool): Randomly capitalise some syllables.
        use_digits      (bool): Inject digits into the password.
        use_symbols     (bool): Inject symbols into the password.
        avoid_ambiguous (bool): Filter ambiguous chars from injections.

    Returns:
        str: Pronounceable password string.
    """
    vowels     = list(VOWELS)
    consonants = list(CONSONANTS)

    if avoid_ambiguous:
        vowels     = [c for c in vowels     if c not in AMBIGUOUS_CHARS]
        consonants = [c for c in consonants if c not in AMBIGUOUS_CHARS]

    # Build syllabic base
    chars = []
    for i in range(length):
        if i % 2 == 0:
            ch = secrets.choice(consonants)
        else:
            ch = secrets.choice(vowels)

        if use_uppercase and secrets.randbelow(5) == 0:  # ~20% chance uppercase
            ch = ch.upper()
        chars.append(ch)

    # Inject mandatory digits
    if use_digits and length > 4:
        pool = [c for c in string.digits if c not in AMBIGUOUS_CHARS] \
               if avoid_ambiguous else list(string.digits)
        inject_count = max(1, length // 6)
        for _ in range(inject_count):
            pos = secrets.randbelow(len(chars))
            chars[pos] = secrets.choice(pool)

    # Inject mandatory symbols
    if use_symbols and length > 6:
        sym_pool = list(POOL_SYMBOLS)
        inject_count = max(1, length // 8)
        for _ in range(inject_count):
            pos = secrets.randbelow(len(chars))
            chars[pos] = secrets.choice(sym_pool)

    return "".join(chars)


# ---------------------------------------------------------------------------
# Pool builders
# ---------------------------------------------------------------------------

def _build_pool(
    use_uppercase:   bool,
    use_lowercase:   bool,
    use_digits:      bool,
    use_symbols:     bool,
    avoid_ambiguous: bool,
) -> str:
    """
    Construct the character pool string from selected classes.

    Args:
        (see generate_password)

    Returns:
        str: Concatenated character pool.
    """
    pool = ""
    if use_lowercase:  pool += POOL_LOWERCASE
    if use_uppercase:  pool += POOL_UPPERCASE
    if use_digits:     pool += POOL_DIGITS
    if use_symbols:    pool += POOL_SYMBOLS

    if avoid_ambiguous:
        pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)

    if not pool:
        raise ValueError("Character pool is empty after applying filters.")

    return pool


def _get_mandatory_chars(
    use_uppercase:   bool,
    use_lowercase:   bool,
    use_digits:      bool,
    use_symbols:     bool,
    avoid_ambiguous: bool,
) -> list:
    """
    Build a list of one guaranteed character from each enabled class.

    This ensures the generated password always satisfies the selected criteria
    (i.e., a password with digits enabled will always contain at least one digit).

    Args:
        (see generate_password)

    Returns:
        list[str]: One character per enabled class.
    """
    mandatory = []

    def _pick(pool_str: str) -> str:
        filtered = [c for c in pool_str if c not in AMBIGUOUS_CHARS] \
                   if avoid_ambiguous else list(pool_str)
        return secrets.choice(filtered) if filtered else ""

    if use_lowercase:  mandatory.append(_pick(POOL_LOWERCASE))
    if use_uppercase:  mandatory.append(_pick(POOL_UPPERCASE))
    if use_digits:     mandatory.append(_pick(POOL_DIGITS))
    if use_symbols:    mandatory.append(_pick(POOL_SYMBOLS))

    return [c for c in mandatory if c]  # filter empty strings


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _secure_shuffle(chars: list) -> None:
    """
    In-place Fisher-Yates shuffle using secrets.randbelow() for CSPRNG randomness.

    Python's random.shuffle() uses the Mersenne Twister — unacceptable for
    security-sensitive operations. This implementation uses the OS CSPRNG.

    Args:
        chars (list): Character list to shuffle in place.
    """
    n = len(chars)
    for i in range(n - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]


def _compute_pool_size(
    use_uppercase:   bool,
    use_lowercase:   bool,
    use_digits:      bool,
    use_symbols:     bool,
    avoid_ambiguous: bool,
) -> int:
    """
    Compute the effective character pool size for entropy calculation.

    Args:
        (see generate_password)

    Returns:
        int: Number of unique characters in the pool.
    """
    pool = _build_pool(use_uppercase, use_lowercase,
                       use_digits, use_symbols, avoid_ambiguous)
    return len(set(pool))


def _compute_entropy(length: int, pool_size: int) -> float:
    """
    Compute entropy: H = L * log2(R).

    Args:
        length    (int): Password length.
        pool_size (int): Character pool size.

    Returns:
        float: Entropy in bits.
    """
    import math
    if pool_size < 2 or length < 1:
        return 0.0
    return length * math.log2(pool_size)


def _clamp(value: int, min_val: int, max_val: int) -> int:
    """
    Clamp an integer between min and max bounds.

    Args:
        value   (int): Input value.
        min_val (int): Lower bound.
        max_val (int): Upper bound.

    Returns:
        int: Clamped value.
    """
    return max(min_val, min(max_val, value))


# ---------------------------------------------------------------------------
# Built-in word list for passphrase generation
# (Subset of EFF Short Wordlist 2.0 — chosen for memorability)
# ---------------------------------------------------------------------------

_WORD_LIST = [
    "apple", "brave", "cloud", "delta", "eagle", "flame", "ghost", "haven",
    "ivory", "jewel", "karma", "laser", "maple", "nexus", "ocean", "pixel",
    "quest", "radar", "steel", "tiger", "ultra", "vault", "waltz", "xenon",
    "yacht", "zebra", "amber", "blaze", "coral", "dunes", "ember", "frost",
    "globe", "haze",  "inbox", "jolts", "knack", "lunar", "mango", "noble",
    "orbit", "plume", "quiet", "river", "storm", "torch", "unity", "vivid",
    "witch", "xray",  "yield", "zonal", "agile", "bloom", "chess", "drift",
    "elite", "flair", "grace", "haven", "ideal", "judge", "kingpin","latch",
    "micro", "nerve", "onset", "prism", "quill", "rebel", "sharp", "twist",
    "unify", "vapor", "winds", "xenial","yours", "zones", "adept", "brisk",
    "crisp", "dense", "epoch", "fixed", "glint", "hoist", "imply", "jaded",
    "kneel", "lodge", "mount", "notch", "optic", "phase", "quirk", "remix",
    "scout", "trove", "untie", "visor", "weave", "oxide", "yearn", "zoned",
]
