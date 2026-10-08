# Password Security Checker
A Python-based password security analyzer that evaluates password strength, detects common weaknesses and patterns, estimates entropy, and checks whether a password has appeared in known data breaches using the Have I Been Pwned (HIBP) Pwned Passwords API.

The project was developed to explore practical password-security concepts including password entropy, pattern detection, breach exposure, API security, and privacy-preserving authentication practices.

## Features
- **Password strength scoring**
  - Rates passwords on a 0–10 scale
  - Provides a corresponding strength classification

- **Password entropy estimation**
  - Estimates entropy based on the character sets used
  - Considers lowercase, uppercase, numeric, and special characters

- **Common password detection**
  - Compares passwords against a dataset of commonly used passwords
  - Uses a locally stored password dataset rather than transmitting passwords to a third-party service

- **Pattern detection**
  - Detects years and common date formats
  - Detects repeated characters
  - Detects repeated character sequences

- **Have I Been Pwned integration**
  - Checks whether a password has appeared in known data breaches
  - Reports the number of times a password has been observed
  - Uses the HIBP Pwned Passwords API's k-anonymity model

- **Secure password input**
  - Uses Python's `getpass` module so passwords are not displayed while being entered

- **Error handling**
  - Handles missing datasets
  - Handles network and API failures
  - Uses a request timeout to prevent the program from hanging indefinitely

## How It Works

The program performs several independent checks on the password.

```text
                    Password
                        │
                        ▼
              ┌─────────────────┐
              │ Input Validation │
              └────────┬────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
      Password      Pattern      Entropy
      Dataset       Analysis     Analysis
      Check
          │            │            │
          └────────────┼────────────┘
                       │
                       ▼
              HIBP Breach Check
                       │
                       ▼
               Risk Assessment
                       │
                       ▼
              Strength + Feedback
```
## Acknowledgements

I used the following sources and research to implement this project:

 - [Rass, S., & König, S. (2018). Password Security as a Game of Entropies. Entropy (Basel, Switzerland), 20(5), 312.](https://doi.org/10.3390/e20050312)
 - [Komanduri S, Shay R, Kelley PG, Mazurek ML, Bauer L, Christin N, Cranor LF, Egelman S (2011) Of Passwords and People: Measuring the Effect of Password-Composition Policies. Proceedings of the SIGCHI Conference on Human Factors in Computing Systems (ACM, New York, NY), pp 2595–2604.](https://www.ece.cmu.edu/~lbauer/papers/2011/chi2011-passwords.pdf)
 - [Shannon-Information Theory Wikipedia](https://en.wikipedia.org/wiki/Shannon_(unit))
 - [NordVPN: What is Password Entropy](https://nordvpn.com/blog/what-is-password-entropy/#:~:text=You%20can%20calculate%20password%20entropy,enter%20your%20password%2Dprotected%20account.)
 - [Microsoft: Create and use strong passwords](https://support.microsoft.com/en-us/windows/create-and-use-strong-passwords-c5cebb49-8c53-4f5e-2bc4-fe357ca048eb)
 - [National Institute of Standards and Technology: Strength of Passwords](https://pages.nist.gov/800-63-4/sp800-63b/passwords/)
 - [List of Common Passwords](https://nordpass.com/most-common-passwords-list/)
 - [Have I been Pwned: API Documentation](https://haveibeenpwned.com/API/V3)


