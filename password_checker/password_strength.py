import re
import math
import os
import csv
import hashlib
import requests
from getpass import getpass

# HIBP-integrated v1:
# added HIBP breach detection and secure password input
# fixed formatting stuff
#error handling 

# Password Strength Evaluator Tool
# Author @ethan-j44


# Common paswords file


# List of common passwords scraped from NordPass
# https://nordpass.com/most-common-passwords-list/

def load_common_passwords():
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, "datasets", "common_passwords.csv")

    try:
        with open(file_path, "r", encoding="cp1252") as f:
            reader = csv.DictReader(f)

            passwords = set(
                row["List:"].strip().lower()
                for row in reader
                if row["List:"]
            )

        print(f"[INFO] Loaded {len(passwords)} common passwords.")
        return passwords

    except FileNotFoundError:
        print("[WARNING] common_passwords.csv not found.")
        return set()


COMMON_PASSWORDS = load_common_passwords()



# Have I Been Pwned; Pwned Passwords API

def check_hibp(password):
    """
    Check whether a password has appeared in known data breaches
    using the Have I Been Pwned Pwned Passwords API.

    Uses k-anonymity:
    -The password is hashed locally
    - Only the first 5 characters of the SHA-1 hash are sent
    - The complete hash is never sent
    """

    # Hash password locally!
    sha1_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    # split hash for k-anonymity
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    headers = {
        "User-Agent": "ethan-j44-Password-Checker",
        "Add-Padding": "true"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=5
        )

        response.raise_for_status()


        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")

            if hash_suffix == suffix:
                return {
                    "compromised": True,
                    "count": int(count)
                }

        # password not found
        return {
            "compromised": False,
            "count": 0
        }

    except requests.RequestException as e:
        return {
            "compromised": None,
            "count": 0,
            "error": str(e)
        }



# Password Entropy


def calculate_entropy(password):
    
    #Estimate password entropy based on the character pool represented in the password
    #This is an estimate and assumes characters are selected independently and randomly from the detected character set
    

    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26

    if re.search(r"[A-Z]", password):
        charset += 26

    if re.search(r"[0-9]", password):
        charset += 10

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset += 32

    if charset == 0:
        return 0

    return len(password) * math.log2(charset)



# Pattern Detection

def detect_dates(password):
    # Detect common date and year patterns.
    

    patterns = [
        r"(19\d{2}|20\d{2})",       # Years: 1999, 2004
        r"\d{2}/\d{2}/\d{4}",       # Dates like: 01/01/2001
        r"\d{8}"                    # Dates like: 01012004
    ]


    matches = []

    for pattern in patterns:
        matches.extend(re.findall(pattern, password))

    return matches


def detect_repeats(password):
    
    #Detect repeated characters and repeated string sequences.
    

    # Repeated characters:
    #aaa
    #1111
    if re.search(r"(.)\1{2,}", password):
        return True

    # Repeated string sequences--
    # abcabc
    # 010101
    if re.search(r"(.{2,})\1", password):
        return True

    return False


def pattern_analysis(password):
    """
    Analyze the password for predictable patterns.
    """

    issues = []

    if detect_dates(password):
        issues.append({
            "type": "date",
            "message": "Contains date or year"
        })

    if detect_repeats(password):
        issues.append({
            "type": "repeat",
            "message": "Contains repeated patterns"
        })

    return issues

# Strength labeling

def get_strength_label(score):
    if score <= 3:
        return "Very Weak"

    elif score <= 5:
        return "Weak"

    elif score <= 7:
        return "Moderate"

    elif score <= 9:
        return "Strong"

    else:
        return "Very Strong"

# Password checker

def check_strength(password):
    """
    Evaluate password strength using:
    - Length
    - Character variety
    - Common password detection
    - Pattern detection
    - Entropy
    - HIBP breach exposure
    """

    score = 0
    feedback = []

    # --------------------------------------------------------
    # Length Check

    if len(password) >= 14:
        score += 3

    elif len(password) >= 12:
        score += 2

    elif len(password) >= 8:
        score += 1
        feedback.append(
            "Using more than 8 characters improves password strength"
        )

    else:
        feedback.append(
            "Use at least 8–14 characters"
        )

    # --------------------------------------------------------
    # Char Variety Check

    variety = 0

    if re.search(r"[a-z]", password):
        variety += 1
    else:
        feedback.append("Add lowercase letters")

    if re.search(r"[A-Z]", password):
        variety += 1
    else:
        feedback.append("Add uppercase letters")

    if re.search(r"[0-9]", password):
        variety += 1
    else:
        feedback.append("Add numbers")

    if re.search(r"[!@#$%^&*]", password):
        variety += 1
    else:
        feedback.append("Add special characters")

    score += min(variety, 4)

    # --------------------------------------------------------
    # Common Password Check

    if password.lower() in COMMON_PASSWORDS:
        score = 0

        feedback.append(
            "This is a very common password!"
        )

    # --------------------------------------------------------
    # Pattern Detection

    patterns = pattern_analysis(password)

    pattern_penalty = 0

    for pattern in patterns:

        if pattern["type"] == "date":
            pattern_penalty += 1

            feedback.append(
                "Contains date/year pattern"
            )

        elif pattern["type"] == "repeat":
            pattern_penalty += 2

            feedback.append(
                "Contains repeated sequence pattern"
            )

    score = max(
        score - pattern_penalty,
        0
    )

    # --------------------------------------------------------
    # Entropy Check

    entropy = calculate_entropy(password)

    if entropy >= 85:
        score += 3

    elif entropy >= 60:
        score += 2

    elif entropy >= 40:
        score += 1

    else:
        score -= 2

        feedback.append(
            "Low randomness (entropy too low)"
        )

    # --------------------------------------------------------
    # HIBP Breach Check

    hibp_result = check_hibp(password)

    if hibp_result["compromised"] is True:

        # immediate no
        score = 0

        feedback.append(
            f"Password has appeared in known data breaches "
            f"{hibp_result['count']:,} times"
        )

    elif hibp_result["compromised"] is None:

        feedback.append(
            "Unable to verify password against known breaches"
        )

    # --------------------------------------------------------
    # Final Score


    score = max(
        0,
        min(10, score)
    )

    return {
        "score": score,
        "entropy": round(entropy, 2),
        "feedback": feedback,
        "label": get_strength_label(score),
        "hibp": hibp_result
    }


# Command Line Interface


if __name__ == "__main__":
    print("       PASSWORD SECURITY CHECKER")

    password = getpass(
        "Enter a password to evaluate: "
    )

    result = check_strength(password)

    # --------------------------------------------------------
    # Password Analysis
    # --------------------------------------------------------

    print("\n--- Password Analysis ---")

    print(
        f"Score: {result['score']}/10"
    )

    print(
        f"Entropy: {result['entropy']} bits"
    )

    print(
        f"Strength: {result['label']}"
    )

    # --------------------------------------------------------
    # HIBP Breach Exposure
    # --------------------------------------------------------

    hibp = result["hibp"]

    print("\n--- Breach Exposure ---")

    if hibp["compromised"] is True:

        print(
            f"!!! Password found in known breaches "
            f"{hibp['count']:,} times."
        )

        print(
            "!!! DO NOT use this password."
        )

    elif hibp["compromised"] is False:

        print(
            "Password was not found in known breaches!"
        )

    else:

        print(
            "!!! Unable to check password exposure help !!!"
        )

        print(
            f"Error: {hibp['error']}"
        )

    # --------------------------------------------------------
    # Feedback
    # --------------------------------------------------------

    if result["feedback"]:

        print("\n--- Feedback ---")

        for feedback in result["feedback"]:
            print(f" - {feedback}")

    else:

        print(
            "\n No major weaknesses detected!"
        )