#!/usr/bin/env python3
import hashlib
import re
import math
import os
import requests
import time
from typing import Dict, List, Tuple, Optional

class PasswordAnalyzer:
    """
    Password Strength Analyzer & Security Audit Tool
    - Accurate breach checks (exact + lowercase only)
    - Realistic crack-time estimates
    - Pattern, dictionary, and common-password detection
    """

    def __init__(self, breach_file_path: str = "breached_password.txt", use_comb_api: bool = False):
        self.use_comb_api = use_comb_api

        # Common passwords (lowercase)
        self.common_passwords = {
            'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
            'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master',
            'sunshine', 'ashley', 'bailey', 'shadow', 'superman', 'password1',
            'welcome', 'admin', 'login', 'passw0rd', 'password123', '1234567890',
            '12345', '1234567', '123456789', 'qwertyuiop', '111111',
            '123123', 'admin123', 'root', 'toor', 'pass', 'test', 'guest',
            'info', 'adm', 'mysql', 'user', 'administrator', 'oracle', 'ftp',
            'pi', 'puppet', 'ansible', 'ec2-user', 'vagrant', 'azureuser',
            'football', 'princess', 'hello123', 'batman', 'charlie', 'internet',
            'service', 'secret', '1q2w3e4r', 'zaq12wsx', 'jordan23', 'iloveyou1',
            'computer', 'daniel', 'jessica', 'qwerty123', 'welcome123', 'root123',
            'test123', 'demo', 'backup', 'temp', 'changeme', 'default'
        }

        # Small dictionary words for substring checks
        self.dictionary_words = {
            'hello', 'world', 'computer', 'security', 'network', 'system',
            'admin', 'user', 'account', 'access', 'secret', 'private',
            'company', 'business', 'office', 'email', 'internet', 'google'
        }

        # Common weak patterns
        self.patterns = {
            'sequential_numbers': r'(012|123|234|345|456|567|678|789|890)',
            'sequential_letters': r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
            'keyboard_pattern': r'(qwerty|asdfgh|zxcvbn|qazwsx|!@#\$%\^)',
            'repeated_chars': r'(.)\1{2,}',
            'year_pattern': r'(19|20)\d{2}'
        }

        # Load or initialize breach DB
        if use_comb_api:
            print("[INFO] Using COMB API for breach detection (online)")
            self.compromised_hashes = set()
            self.breach_db_size = 3_200_000_000
        else:
            self.compromised_hashes = self._load_compromised_hashes(breach_file_path)
            self.breach_db_size = len(self.compromised_hashes)
            print(f"[INFO] Loaded {self.breach_db_size:,} compromised password hashes (local)")

    def _load_compromised_hashes(self, breach_file_path: str = None) -> set:
        """
        Load a breach file of plaintext passwords (one per line) and store SHA-256 hashes.
        To avoid false positives we only store:
          - exact password hash
          - lowercase password hash
        (Do NOT generate multiple case variants)
        """
        compromised = set()

        if breach_file_path and os.path.exists(breach_file_path):
            try:
                print(f"[INFO] Loading breach database from: {breach_file_path}")
                with open(breach_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        pwd = line.strip()
                        if not pwd:
                            continue
                        # If the line is "user:password" try to extract last field
                        if ':' in pwd:
                            pwd = pwd.split(':')[-1]
                        compromised.add(hashlib.sha256(pwd.encode()).hexdigest())
                        compromised.add(hashlib.sha256(pwd.lower().encode()).hexdigest())
                print(f"[SUCCESS] Loaded {len(compromised):,} password hashes from file")
                return compromised
            except Exception as e:
                print(f"[ERROR] Failed to load breach file: {e}")

        # Default small breach dataset (plaintext list). Only add exact + lowercase hashes.
        default_passwords = [
            'password', '123456', '123456789', '12345678', '12345', '1234567',
            '1234567890', 'qwerty', 'abc123', 'football', 'iloveyou', 'admin',
            'welcome', 'monkey', 'login', 'princess', 'sunshine', 'passw0rd',
            'password1', 'letmein', 'dragon', 'admin123', 'root', 'hello123',
            'trustno1', 'batman', 'superman', 'charlie', 'shadow', 'master',
            'internet', 'service', 'secret', 'qwertyuiop', '1q2w3e4r',
            'abc@123', 'zaq12wsx', 'baseball', 'jordan23', 'iloveyou1',
            'computer', 'daniel', 'jessica', 'password123', '111111',
            '123123', 'qwerty123', 'welcome123', 'admin@123', 'root123',
            'test123', 'demo', 'backup', 'temp', 'changeme', 'pass',
            'test', 'guest', 'info', 'user', 'default', 'mysql',
            'administrator', 'oracle', 'ftp', 'toor'
        ]

        for pwd in default_passwords:
            compromised.add(hashlib.sha256(pwd.encode()).hexdigest())
            compromised.add(hashlib.sha256(pwd.lower().encode()).hexdigest())

        print(f"[INFO] Using default breach dataset ({len(compromised):,} hashes)")
        return compromised

    def check_breach_comb_api(self, password: str) -> Tuple[bool, int]:
        """
        (Optional) Example of calling an online COMB-like API.
        Note: this is a placeholder; update endpoint and parameters for a real service.
        """
        try:
            url = "https://api.proxynova.com/comb"
            params = {'query': password, 'start': 0, 'limit': 1}
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                count = data.get('count', 0)
                return (count > 0, count)
            return (False, 0)
        except Exception:
            return (False, 0)

    def calculate_entropy(self, password: str) -> float:
        """Calculate entropy bits based on actual character classes present."""
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'[0-9]', password): charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password): charset_size += 32
        return len(password) * math.log2(charset_size) if charset_size else 0.0

    def estimate_crack_time(self, password: str, is_common: bool, is_breached: bool, dict_words: List[str]) -> Dict[str, str]:
        """
        Return human-friendly crack-time estimates.
        If password is common, dictionary-derived, or found in breach DB => Instant.
        Otherwise compute entropy-based brute-force time for different attacker profiles.
        """
        # If definitely weak / breached -> instant (attacker uses dictionary/known lists)
        if is_common or is_breached or (dict_words and len(dict_words) > 0):
            return {
                'online_throttled': "Instant (< 0.001 seconds)",
                'online_unthrottled': "Instant (< 0.001 seconds)",
                'offline_slow': "Instant (< 0.001 seconds)",
                'offline_fast': "Instant (< 0.001 seconds)"
            }

        # Brute-force model
        entropy = self.calculate_entropy(password)
        combinations = math.pow(2.0, entropy)

        # guesses/sec for profiles (example realistic ranges)
        scenarios = {
            # Online protected/unprotected are small numbers (but online brute force is unrealistic)
            'online_throttled': 1.0,         # 1 attempt/sec (very conservative)
            'online_unthrottled': 20.0,      # 20 attempts/sec (less-protected)
            # Offline (hash cracking) speeds depend on algorithm; these are example values
            'offline_slow': 1e6,             # 1 million guesses/sec (CPU-ish)
            'offline_fast': 1e10             # 10 billion guesses/sec (GPU cluster, fast hashes)
        }

        return {name: self._format_time(combinations / speed) for name, speed in scenarios.items()}

    def _format_time(self, seconds: float) -> str:
        """Format seconds into human readable units with thresholds."""
        if seconds < 0.001:
            return "Instant (< 0.001 seconds)"
        if seconds < 1:
            return f"{seconds:.3f} seconds"
        if seconds < 60:
            return f"{seconds:.1f} seconds"

        minutes = seconds / 60.0
        if minutes < 60:
            return f"{minutes:.1f} minutes"

        hours = minutes / 60.0
        if hours < 24:
            return f"{hours:.1f} hours"

        days = hours / 24.0
        if days < 30:
            return f"{days:.1f} days"

        months = days / 30.0
        if months < 12:
            return f"{months:.1f} months"

        years = months / 12.0
        if years < 1000:
            return f"{years:.1f} years"

        return f"{years:.2e} years"

    def check_common_passwords(self, password: str) -> bool:
        return password.lower() in self.common_passwords

    def check_dictionary(self, password: str) -> List[str]:
        return [word for word in self.dictionary_words if word in password.lower()]

    def check_patterns(self, password: str) -> List[str]:
        return [name.replace('_', ' ') for name, pat in self.patterns.items()
                if re.search(pat, password.lower())]

    def check_breach_database(self, password: str) -> Tuple[bool, Optional[int]]:
        """
        Check breach database for password.
        Only check exact and lowercase hash to avoid false positives.
        """
        if self.use_comb_api:
            return self.check_breach_comb_api(password)

        pwd_hash_exact = hashlib.sha256(password.encode()).hexdigest()
        pwd_hash_lower = hashlib.sha256(password.lower().encode()).hexdigest()

        if pwd_hash_exact in self.compromised_hashes:
            return (True, None)
        if pwd_hash_lower in self.compromised_hashes:
            return (True, None)

        return (False, None)

    def calculate_strength_score(self, password: str, is_breached: bool, patterns: List[str], dict_words: List[str]) -> Tuple[int, str]:
        """Compute a 0-100 strength score and a textual rating."""
        score = 0
        length = len(password)

        # Length scoring
        if length >= 16:
            score += 35
        elif length >= 14:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 10:
            score += 20
        elif length >= 8:
            score += 12
        elif length >= 6:
            score += 5

        # Character diversity
        types = sum(bool(re.search(regex, password)) for regex in [r'[a-z]', r'[A-Z]', r'[0-9]', r'[^a-zA-Z0-9]'])
        score += int(types * 7.5)

        # Entropy bonus (scaled)
        entropy = self.calculate_entropy(password)
        score += min(25, int(entropy // 3))

        # Deductions
        if password.lower() in self.common_passwords:
            score -= 40
        if is_breached:
            score -= 30
        score -= len(patterns) * 8
        score -= len(dict_words) * 5

        score = max(0, min(100, score))
        rating_index = min(4, int(score // 20))
        rating = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][rating_index]
        return score, rating

    def analyze(self, password: str) -> Dict:
        """Run full analysis and return a dictionary of results."""
        if not password:
            return {"error": "Password cannot be empty"}

        is_common = self.check_common_passwords(password)
        is_breached, breach_count = self.check_breach_database(password)
        patterns = self.check_patterns(password)
        dict_words = self.check_dictionary(password)

        entropy = self.calculate_entropy(password)
        score, rating = self.calculate_strength_score(password, is_breached, patterns, dict_words)

        crack_times = self.estimate_crack_time(password, is_common, is_breached, dict_words)

        composition = {
            'length': len(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'[0-9]', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password))
        }

        recommendations = []
        if len(password) < 12:
            recommendations.append("Increase length to at least 12 characters")
        if not composition['has_uppercase']:
            recommendations.append("Add uppercase letters")
        if not composition['has_lowercase']:
            recommendations.append("Add lowercase letters")
        if not composition['has_digits']:
            recommendations.append("Add numbers")
        if not composition['has_special']:
            recommendations.append("Add special characters")
        if is_common:
            recommendations.append("⚠️ CRITICAL: This is a commonly used password - NEVER use it!")
        if is_breached:
            recommendations.append("⚠️ CRITICAL: This password appears in breach database - Change immediately!")
        if patterns:
            recommendations.append(f"Avoid patterns: {', '.join(patterns)}")
        if dict_words:
            recommendations.append(f"Avoid dictionary words: {', '.join(dict_words)}")

        return {
            'score': score,
            'rating': rating,
            'entropy_bits': round(entropy, 2),
            'composition': composition,
            'length': len(password),
            'crack_time_estimates': crack_times,
            'vulnerabilities': {
                'is_common_password': is_common,
                'found_in_breach': is_breached,
                'breach_occurrences': breach_count,
                'vulnerable_patterns': patterns,
                'dictionary_words': dict_words
            },
            'breach_database_size': self.breach_db_size,
            'breach_database_type': 'COMB API' if self.use_comb_api else 'Local Database',
            'recommendations': recommendations,
            'hash_sha256': hashlib.sha256(password.encode()).hexdigest()
        }

    def print_report(self, analysis: Dict) -> None:
        """Pretty-print an analysis dictionary."""
        if 'error' in analysis:
            print(f"Error: {analysis['error']}")
            return

        print("\n" + "="*70)
        print("PASSWORD SECURITY AUDIT REPORT")
        print("="*70)

        print(f"\n[STRENGTH ASSESSMENT]")
        print(f"Score: {analysis['score']}/100")
        print(f"Rating: {analysis['rating']}")
        print(f"Entropy: {analysis['entropy_bits']} bits")

        comp = analysis['composition']
        print(f"\n[COMPOSITION]")
        print(f"Length: {analysis['length']} characters")
        print(f"Lowercase: {'✓' if comp['has_lowercase'] else '✗'}")
        print(f"Uppercase: {'✓' if comp['has_uppercase'] else '✗'}")
        print(f"Digits: {'✓' if comp['has_digits'] else '✗'}")
        print(f"Special Characters: {'✓' if comp['has_special'] else '✗'}")

        print(f"\n[CRACK TIME ESTIMATES]")
        for scenario, time_str in analysis['crack_time_estimates'].items():
            print(f"{scenario.replace('_', ' ').title()}: {time_str}")

        vuln = analysis['vulnerabilities']
        print(f"\n[VULNERABILITY ASSESSMENT]")
        print(f"Breach Database: {analysis['breach_database_type']} ({analysis['breach_database_size']:,} credentials)")
        print(f"Common Password: {'YES ⚠️ DANGER!' if vuln['is_common_password'] else 'No ✓'}")
        print(f"Found in Breach: {'YES ⚠️ DANGER!' if vuln['found_in_breach'] else 'No ✓'}")

        if vuln['vulnerable_patterns']:
            print(f"Patterns Found: {', '.join(vuln['vulnerable_patterns'])}")
        if vuln['dictionary_words']:
            print(f"Dictionary Words: {', '.join(vuln['dictionary_words'])}")

        if analysis['recommendations']:
            print(f"\n[RECOMMENDATIONS]")
            for i, rec in enumerate(analysis['recommendations'], 1):
                print(f"{i}. {rec}")

        print(f"\n[HASH]")
        print(f"SHA-256: {analysis['hash_sha256']}")

        print("\n" + "="*70)

def main():
    print("Password Strength Analyzer & Security Audit Tool")
    print("="*70)

    print("\n[BREACH DATABASE OPTIONS]")
    print("1. Local Database (Default - includes common passwords in a small dataset)")
    print("2. COMB API (Internet Required - example online lookup)")

    choice = input("\nSelect option (1 or 2) [default: 1]: ").strip() or "1"

    if choice == "2":
        analyzer = PasswordAnalyzer(use_comb_api=True)
    else:
        analyzer = PasswordAnalyzer()

    print("\n[INTERACTIVE MODE]")
    print("Enter 'quit' to exit")
    print("\nTry testing with: 'password', 'Password', '123456', 'admin', 'MyUniqueVeryLongPassword123!'\n")

    while True:
        password = input("Enter password to analyze: ").strip()
        if password.lower() == 'quit':
            print("\nThank you for using Password Analyzer!")
            break
        if not password:
            print("Error: Password cannot be empty\n")
            continue

        analysis = analyzer.analyze(password)
        analyzer.print_report(analysis)

        if analyzer.use_comb_api:
            time.sleep(1)

if __name__ == "__main__":
    main()
