#!/usr/bin/env python3
import re
import sys
import subprocess
import math
import json
import hashlib
from collections import Counter
from pathlib import Path

SECRET_PATTERNS = [

    # ─────────────────────────────────────────────
    # AWS
    # ─────────────────────────────────────────────

    (
        "AWS Access Key",
        re.compile(
            r"\bAKIA[0-9A-Z]{16}\b"
        ),
    ),

    (
        "AWS Temporary Access Key",
        re.compile(
            r"\bASIA[0-9A-Z]{16}\b"
        ),
    ),

    (
        "AWS Secret Access Key",
        re.compile(
            r"(?i)\b(?:aws_secret_access_key|aws_secret_key)\b"
            r"\s*[:=]\s*['\"]([^'\"]{20,})['\"]"
        ),
    ),


    # ─────────────────────────────────────────────
    # NVIDIA
    # ─────────────────────────────────────────────

    (
        "NVIDIA API Key",
        re.compile(
            r"\bnvapi-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # GitHub
    # ─────────────────────────────────────────────

    (
        "GitHub Personal Access Token",
        re.compile(
            r"\bghp_[A-Za-z0-9]{36}\b"
        ),
    ),

    (
        "GitHub OAuth Token",
        re.compile(
            r"\bgho_[A-Za-z0-9]{36}\b"
        ),
    ),

    (
        "GitHub User-to-Server Token",
        re.compile(
            r"\bghu_[A-Za-z0-9]{36}\b"
        ),
    ),

    (
        "GitHub Server-to-Server Token",
        re.compile(
            r"\bghs_[A-Za-z0-9]{36}\b"
        ),
    ),

    (
        "GitHub Fine-Grained Token",
        re.compile(
            r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # GitLab
    # ─────────────────────────────────────────────

    (
        "GitLab Personal Access Token",
        re.compile(
            r"\bglpat-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Slack
    # ─────────────────────────────────────────────

    (
        "Slack Token",
        re.compile(
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Stripe
    # ─────────────────────────────────────────────

    (
        "Stripe Secret Key",
        re.compile(
            r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"
        ),
    ),

    (
        "Stripe Restricted Key",
        re.compile(
            r"\brk_(?:live|test)_[A-Za-z0-9]{16,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # OpenAI
    # ─────────────────────────────────────────────

    (
        "OpenAI API Key",
        re.compile(
            r"\bsk-[A-Za-z0-9_-]{20,}\b"
        ),
    ),

    (
        "OpenAI Project API Key",
        re.compile(
            r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Anthropic
    # ─────────────────────────────────────────────

    (
        "Anthropic API Key",
        re.compile(
            r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Google / GCP
    # ─────────────────────────────────────────────

    (
        "Google API Key",
        re.compile(
            r"\bAIza[0-9A-Za-z_-]{35}\b"
        ),
    ),

    (
        "Google OAuth Client Secret",
        re.compile(
            r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Discord
    # ─────────────────────────────────────────────

    (
        "Discord Bot Token",
        re.compile(
            r"\b[A-Za-z0-9_-]{24,28}\."
            r"[A-Za-z0-9_-]{6}\."
            r"[A-Za-z0-9_-]{25,}\b"
        ),
    ),

    (
        "Discord Webhook",
        re.compile(
            r"https://discord(?:app)?\.com/api/webhooks/"
            r"\d{15,25}/[A-Za-z0-9_-]{20,}"
        ),
    ),


    # ─────────────────────────────────────────────
    # Telegram
    # ─────────────────────────────────────────────

    (
        "Telegram Bot Token",
        re.compile(
            r"\b\d{8,12}:[A-Za-z0-9_-]{35}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # PyPI
    # ─────────────────────────────────────────────

    (
        "PyPI API Token",
        re.compile(
            r"\bpypi-[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # npm
    # ─────────────────────────────────────────────

    (
        "npm Access Token",
        re.compile(
            r"\bnpm_[A-Za-z0-9]{30,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # SendGrid
    # ─────────────────────────────────────────────

    (
        "SendGrid API Key",
        re.compile(
            r"\bSG\.[A-Za-z0-9_-]{20,}\."
            r"[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Twilio
    # ─────────────────────────────────────────────

    (
        "Twilio API Key",
        re.compile(
            r"\bSK[0-9a-fA-F]{32}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Heroku
    # ─────────────────────────────────────────────

    (
        "Heroku API Key",
        re.compile(
            r"(?i)\bheroku[_-]?(?:api[_-]?)?key\b"
            r"\s*[:=]\s*['\"]([0-9a-f-]{20,})['\"]"
        ),
    ),


    # ─────────────────────────────────────────────
    # HashiCorp / Terraform
    # ─────────────────────────────────────────────

    (
        "HashiCorp Vault Token",
        re.compile(
            r"\bhvs\.[A-Za-z0-9_-]{20,}\b"
        ),
    ),

    (
        "Terraform Cloud Token",
        re.compile(
            r"\b[a-zA-Z0-9]{14,}\.atlasv1\."
            r"[A-Za-z0-9_-]{20,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # SSH / Private Keys
    # ─────────────────────────────────────────────

    (
        "RSA Private Key",
        re.compile(
            r"-----BEGIN RSA PRIVATE KEY-----"
        ),
    ),

    (
        "EC Private Key",
        re.compile(
            r"-----BEGIN EC PRIVATE KEY-----"
        ),
    ),

    (
        "DSA Private Key",
        re.compile(
            r"-----BEGIN DSA PRIVATE KEY-----"
        ),
    ),

    (
        "OpenSSH Private Key",
        re.compile(
            r"-----BEGIN OPENSSH PRIVATE KEY-----"
        ),
    ),

    (
        "Generic Private Key",
        re.compile(
            r"-----BEGIN PRIVATE KEY-----"
        ),
    ),

    (
        "Encrypted Private Key",
        re.compile(
            r"-----BEGIN ENCRYPTED PRIVATE KEY-----"
        ),
    ),


    # ─────────────────────────────────────────────
    # JWT
    # ─────────────────────────────────────────────

    (
        "JWT Token",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\b"
        ),
    ),


    # ─────────────────────────────────────────────
    # Basic Auth / Bearer credentials
    # ─────────────────────────────────────────────

    (
        "Bearer Token",
        re.compile(
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"
        ),
    ),

    (
        "Basic Authentication",
        re.compile(
            r"(?i)\bBasic\s+[A-Za-z0-9+/=]{20,}"
        ),
    ),
]

# Used by the entropy check to give values some context.
SECRET_CONTEXT_PATTERN = re.compile(
    r"""(?ix)\b(
        password|
        passwd|
        pwd|
        passphrase|
        secret|
        api[_-]?key|
        apikey|
        access[_-]?key|
        secret[_-]?key|
        auth[_-]?token|
        bearer[_-]?token|
        client[_-]?secret|
        client[_-]?key|
        private[_-]?key|
        signing[_-]?key|
        encryption[_-]?key|
        credential|
        credentials|
        token
    )\b"""
)

# Things like IDs and hashes
NEUTRAL_CONTEXT_PATTERN = re.compile(
    r"""(?ix)\b(
        id|
        user[_-]?id|
        account[_-]?id|
        request[_-]?id|
        object[_-]?id|
        uuid|
        guid|
        hash|
        sha|
        sha1|
        sha224|
        sha256|
        sha384|
        sha512|
        md5|
        checksum|
        digest|
        etag|
        commit|
        revision
    )\b"""
)

# Detects values assigned to variables/fields that strongly indicate secrets. leik password = 12345.
SECRET_VARIABLE_PATTERN = re.compile(
    r"""(?ix)
    \b(
        password|
        passwd|
        pwd|
        passphrase|
        secret|
        api[_-]?key|
        apikey|
        access[_-]?key|
        secret[_-]?key|
        auth[_-]?token|
        bearer[_-]?token|
        client[_-]?secret|
        client[_-]?key|
        private[_-]?key|
        signing[_-]?key|
        encryption[_-]?key|
        credential|
        credentials|
        token
    )\b
    \s*(?:=|:)
    \s*
    ["'`]?
    ([^\s"'`,;]+)
    ["'`]?
    """
)


def get_git_dir():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return Path(result.stdout.strip())
    except OSError:
        pass
    return Path(".git")


# That shannon entropy in scanner.py is a good idea honestly, but high entropy values can be legitimate hashes, IDs, test values, etc. etc...
# So to prevent false positives all the time, this module adds to a whitelist and ignores it on next scanner run
# We never store the original value in the whitelist but instead a sha256 fingerprint of it, as good security practice.
WHITELIST_FILE = get_git_dir() / "secrets-whitelist.json"


def encode(value):
    # SHA-256 is used as a fingerprint, not encryption.
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_whitelist():
    # No whitelist means nothing has been approved yet.
    if not WHITELIST_FILE.exists():
        return set()

    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        # A set gives us fast lookups when checking detected values.
        return set(data.get("values", []))

    except (OSError, json.JSONDecodeError):
        # If the whitelist can't be read, treat it as empty and ask again.
        return set()

def is_whitelisted(value, whitelist=None):
    if whitelist is None:
        whitelist = load_whitelist()

    return encode(value) in whitelist

def whitelist_value(value, whitelist=None):
    if whitelist is None:
        whitelist = load_whitelist()

    fingerprint = encode(value)

    if fingerprint in whitelist:
        return
     # Keep the in-memory whitelist updated so repeated values in the
      # same scan are also skipped.
    whitelist.add(fingerprint)

    WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Sorting keeps whitelist.json deterministic and easier to maintain.
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {  "values": sorted(whitelist) },
            f, indent=4
        )

PLACEHOLDER_VALUES = {
    "changeme", "change_me",
    "change-me", "your_password",
    "your_password_here",
    "your_api_key", "your_api_key_here",
    "password",    "passwd",    "example",
    "example_password",    "placeholder",
    "redacted",    "replace_me",
    "replace-me",    "todo","test",
    "testing",    "xxxx",
    "xxxxxxxx",    "1234",
    "123456",    "null",
    "none",    "undefined",
}

ENTROPY_THRESHOLD = 4.0
MIN_LENGTH_FOR_ENTROPY_CHECK = 8

def calculate_entropy(s):
        # Entropy is useful for spotting random-looking strings,
    # but by itself it doesn't mean "secret". UUIDs and hashes
    # can have high entropy too. And it can be risky to single handlely treat every hash/UUID as secret and blocking push
    # a better treatment would treat them as suspicious or for a second revision but not treating as leaked secret
    if not s:
        return 0.0

    s = s.strip()

    if len(s) < 2:
        return 0.0

    counts = Counter(s)
    length = len(s)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def is_placeholder(value):
    value = value.strip().lower()
    if value in PLACEHOLDER_VALUES:
        return True
    # Things like ${API_KEY}, <PASSWORD> and {{TOKEN}} are
    # usually variable/template placeholders from previosuly declared variables, not real secrets.
    if (
        (value.startswith("${") and value.endswith("}"))
        or (value.startswith("<") and value.endswith(">"))
        or (value.startswith("{{") and value.endswith("}}"))
    ):
        return True

    return False


def is_binary(filepath): #refactor of that binary check previously added.
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)

        return b"\x00" in chunk

    except OSError:
        return True


def show_whitelist_prompt(filepath, line_number, value, entropy):
    print()
    print(
        f"[possible secret found] "
        f"{filepath}:{line_number} > {value}"
    )
    print(
        f"[!] Entropy: {entropy:.2f}"
    )
    print(
        "[!] User Approval Required. "
        "Whitelist this secret? (y/n)"
    )


def get_tracked_files(): #refactor #2 
    result = subprocess.run( ["git", "ls-files"], capture_output=True, text=True )
    if result.returncode != 0:
        print("[ERROR] Could not get Git tracked files.", file=sys.stderr)
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        return None
    return result.stdout.splitlines()

def ask_user(prompt):
    try:
        if sys.stdin.isatty():
            stream = sys.stdin
            owned = False
        else:
            stream = open("/dev/tty", "r")
            owned = True
    except OSError as exc:
        print("[!] No terminal input available, automatically blocking push", file=sys.stderr)
        return None
    try:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        answer = stream.readline()
    finally:
        if owned:
            stream.close()
    if not answer:
        print("[!] No answer received. rejecting push!", file=sys.stderr)
        return None
    return answer.strip().lower()


def main():
    tracked_files = get_tracked_files()
    if tracked_files is None:
        # 2 means the scanner couldn't complete.
        return 2
    if not tracked_files:
        print("[OK] No Git-tracked files to scan.")
        return 0
    # Used by the entropy fallback to find quoted values.
    string_pattern = re.compile(
        r'''(?:"([^"\r\n]+)"|'([^'\r\n]+)'|`([^`\r\n]+)`)'''
    )
    # Load once and keep the set updated while scanning.
    whitelist = load_whitelist()
    detected_locations = []
    found_secrets = False
    scan_errors = False

    for filepath in tracked_files:
    
        if filepath.endswith("scanner.py"):
            continue
        if filepath.startswith("modules/"): # ignores its own modules and regex patterns
            continue
        if filepath.endswith(".md"):
            continue

        try:
            if is_binary(filepath):
                continue

        except OSError as exc:
            print(
                f"[ERROR] Could not inspect {filepath}: {exc}",
                file=sys.stderr,
            )
            scan_errors = True
            continue

        try:
            with open(
                filepath,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as f:
                #in here we start the loops for verification.
                for number, line in enumerate(f, start=1):

                    line_has_known_secret = False

                    # -----------------------------------
                    # | Provider pattern identification |
                    # -----------------------------------
                    # Known provider formats don't need entropy to confirm
                    # them. If the format matches, report it immediately.
                    for label, pattern in SECRET_PATTERNS:
                        match = pattern.search(line)

                        if not match:
                            continue

                        print(
                            f"[!] Possible {label} in "
                            f"{filepath} (line {number}): "
                            f"{match.group()}"
                        )

                        found_secrets = True
                        line_has_known_secret = True

                        detected_locations.append(
                            (filepath, number)
                        )

                    # Entropy is only the fallback if the hardcoded patterns are not detected, but as informed high entropy never necessarily means a secret,
                    # but its important to raise a suspicion tho
                    if line_has_known_secret:
                        continue
                    has_secret_context = SECRET_CONTEXT_PATTERN.search(line)
                    has_neutral_context = NEUTRAL_CONTEXT_PATTERN.search(line)
                    
                    if not has_secret_context and not has_neutral_context:
                        continue

                    secret_variable_matches = list(
                        SECRET_VARIABLE_PATTERN.finditer(line)
                    )
                    
                    if secret_variable_matches:
                        candidates = [
                            (match.group(2).strip(), True)
                            for match in secret_variable_matches
                        ]
                    else:
                        candidates = [
                            (
                                next(
                                    (
                                        group
                                        for group in match.groups()
                                        if group is not None
                                    ),
                                    "",
                                ).strip(),
                                False,
                            )
                            for match in string_pattern.finditer(line)
                        ]
                    
                    for value, is_secret_variable in candidates:
                    
                        if len(value) < MIN_LENGTH_FOR_ENTROPY_CHECK:
                            continue
                        
                        if is_placeholder(value):
                            continue
                        
                        if is_whitelisted(value, whitelist):
                            continue
                        
                        entropy = calculate_entropy(value)
                        
                        # Explicit secret assignments do not require high entropy.
                        if not is_secret_variable and entropy < ENTROPY_THRESHOLD:
                            continue
                        
                        show_whitelist_prompt(
                            filepath,
                            number,
                            value,
                            entropy,
                        )
                        
                        while True:
                            answer = ask_user("> ")
                            if answer is None:
                                print()
                                print("[!] No approval received.")
                                print("[!] Push blocked.")
                                return 1
                        
                            if answer in ("y", "yes"):
                                whitelist_value(
                                    value,
                                    whitelist,
                                )
                        
                                print(
                                    "[OK] Secret whitelisted. "
                                    "Continuing scan."
                                )
                                break
                        
                            if answer in ("n", "no"):
                                print()
                                print("[!] Secret rejected.")
                        
                                detected_locations.append(
                                    (filepath, number)
                                )
                        
                                print(
                                    "\n[!] Push blocked - secrets "
                                    "were found on:"
                                )
                        
                                for detected_filepath, detected_line in (
                                    detected_locations
                                ):
                                    print(
                                        f"- {detected_filepath}:"
                                        f"{detected_line}"
                                    )
                        
                                return 1
                        
                            print(
                                "[!] Please answer 'y' or 'n'."
                            )

                        # -----------------------------------
                        # | Last resource, find by entropy  |
                        # -----------------------------------
                        # IDs and hashes can also have high entropy.
                        # However, they can be considered a ''secret'' or not, certain codes will have hardcoded
                        # high entropy numbers like UUID or user ids etc etc.. but i suppose it is best
                        # to raise suspicion aswell, 

                        
                        show_whitelist_prompt(
                            filepath,
                            number,
                            value,
                            entropy,
                        )

                        while True:
                            answer = ask_user("> ")
                            
                            if answer is None:
                                print()
                                print(
                                    "[!] No approval received."
                                )
                                print(
                                    "[!] Push blocked."
                                )
                                return 1
                        
                            if answer in ("y", "yes"):
                                whitelist_value(
                                    value,
                                    whitelist,
                                )

                                print(
                                    "[OK] Secret whitelisted. "
                                    "Continuing scan."
                                )
                                break

                            if answer in ("n", "no"):
                                print()
                                print(
                                    "[!] Secret rejected."
                                )

                                detected_locations.append(
                                    (filepath, number)
                                )

                                print(
                                    "\n[!] Push blocked - secrets "
                                    "were found on:"
                                )

                                for detected_filepath, detected_line in (
                                    detected_locations
                                ):
                                    print(
                                        f"- {detected_filepath}:"
                                        f"{detected_line}"
                                    )

                                return 1

                            print(
                                "[!] Please answer 'y' or 'n'."
                            )

                        continue

        except OSError as exc:
            print(
                f"[ERROR] Could not read {filepath}: {exc}",
                file=sys.stderr,
            )
            scan_errors = True

    if scan_errors:
        print("\n[ERROR] Some files could not be scanned.")
        print("[ERROR] Push blocked because the scan was incomplete.")
        return 2

    if found_secrets:
        print("\n[!] Secrets detected — push blocked.")
        print("[!] Secrets were found on:")

        for filepath, number in detected_locations:
            print(f"- {filepath}:{number}")

        return 1

    print("[OK] No possible secrets detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
