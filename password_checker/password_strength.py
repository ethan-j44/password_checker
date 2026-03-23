import re
import math
import os
import csv

# Password Strength Evaluator Tool
# Ethan Jones

# list of common passwords scraped from NordVpn 
# https://nordpass.com/most-common-passwords-list/

def load_common_passwords():
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, "datasets", "common_passwords.csv")

    try:
        with open(file_path, "r", encoding="cp1252") as f:
            reader = csv.DictReader(f)  # uses header row
            passwords = set(row["List:"].strip().lower() for row in reader if row["List:"])
            
        print(f"[INFO] Loaded {len(passwords)} common passwords.")
        return passwords

    except FileNotFoundError:
        print("[WARNING] common_passwords.csv not found.")
        return set()

COMMON_PASSWORDS = load_common_passwords()

# Password entropy calculation (amount of information entropy, measured in shannon)
# https://en.wikipedia.org/wiki/Shannon_(unit) 
# https://nordvpn.com/blog/what-is-password-entropy/#:~:text=You%20can%20calculate%20password%20entropy,enter%20your%20password%2Dprotected%20account.
# also see:
# Rass, Stefan, and Sandra König. “Password Security as a Game of Entropies.” 
# Entropy (Basel, Switzerland) vol. 20,5 312. 25 Apr. 2018, doi:10.3390/e20050312

def calculate_entropy(password):
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

# pattern detection for dates, repeated chars

def detect_dates(password):
    patterns = [
        r"(19\d{2}|20\d{2})",      # years in format 1999, 2004
        r"\d{2}/\d{2}/\d{4}",      # date in format 01/01/2001
        r"\d{8}"                   # date in format 01012004
    ]

    matches = []
    for p in patterns:
        matches.extend(re.findall(p, password))

    return matches

def detect_repeats(password):
    # Repeated characters (aaa, 1111)
    if re.search(r"(.)\1{2,}", password):
        return True

    # Repeated string sequences (abcabc, 010101)
    if re.search(r"(.{2,})\1", password):
        return True

    return False

def pattern_analysis(password):
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

# score strength labeling
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

#strength checking
# see:
# https://support.microsoft.com/en-us/windows/create-and-use-strong-passwords-c5cebb49-8c53-4f5e-2bc4-fe357ca048eb
# https://pages.nist.gov/800-63-4/sp800-63b/passwords/  
# Scoring based on findings of this research (length and entropy are most significant in my model):
# Komanduri S, Shay R, Kelley PG, Mazurek ML, Bauer L, Christin N, Cranor LF, Egelman S (2011) Of Passwords and People: Measuring the Effect of Password-Composition Policies. 
# Proceedings of the SIGCHI Conference on Human Factors in Computing Systems (ACM, New York, NY), pp 2595–2604. 
# Available at https://www.ece.cmu.edu/~lbauer/papers/2011/chi2011-passwords.pdf
def check_strength(password):
    score = 0
    feedback = []

    # Length check (score: 0-3)
    if len(password) >= 14:
        score += 3
    elif len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        feedback.append("Using more than 8 characters improves password strength")
    else:
        feedback.append("Use at least 8–14 characters")

    # Character types check (score 0-4)
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

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("This is a very common password!")

    # Pattern detection
    patterns = pattern_analysis(password)
    pattern_penalty = 0

    for p in patterns:
        if p["type"] == "date":
            pattern_penalty += 1
            feedback.append("Contains date/year pattern")

        elif p["type"] == "repeat":
            pattern_penalty += 2
            feedback.append("Contains repeated sequence pattern")

    score = max(score - pattern_penalty, 0)

    # Entropy check
    entropy = calculate_entropy(password)
    if entropy >= 85:
        score += 3
    elif entropy >= 60:
        score += 2
    elif entropy >= 40:
        score += 1
    else:
        score -= 2
        feedback.append("Low randomness (entropy too low)")
    
    score = max(0, min(10, score))

    return {
        "score": score,
        "entropy": round(entropy, 2),
        "feedback": feedback,
        "label": get_strength_label(score)
    }


# CLI:

if __name__ == "__main__":
    password = input("Enter a password to evaluate: ")

    result = check_strength(password)

    print("\n--- Password Analysis ---")
    print(f"Score: {result['score']}/10")
    print(f"Entropy: {result['entropy']} bits")
    print(f"Strength: {result['label']}")


    if result["feedback"]:
        print("\n Feedback:")
        for f in result["feedback"]:
            print(f" - {f}")
    else:
        print("\n Strong password!")