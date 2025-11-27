import hashlib
import re
import math
import os
import requests
import time
from typing import Dict, List, Tuple, Optional

class PasswordAnalyzer:
    """
    Comprehensive password security assessment tool following NIST guidelines.
    Evaluates password strength, vulnerability patterns, and breach database checks.
    Supports local breach database and COMB API integration.
    """
    
    def __init__(self, breach_file_path: str = "breached_password.txt", use_comb_api: bool = False):
        self.use_comb_api = use_comb_api
        
        # Common passwords and dictionary words
        self.common_passwords = {
            'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
            'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master',
            'sunshine', 'ashley', 'bailey', 'shadow', 'superman', 'password1',
            'welcome', 'admin', 'login', 'passw0rd', 'password123', '1234567890'
        }
        
        # Common dictionary words
        self.dictionary_words = {
            'hello', 'world', 'computer', 'security', 'network', 'system',
            'admin', 'user', 'account', 'access', 'secret', 'private',
            'company', 'business', 'office', 'email', 'internet', 'google'
        }
        
        # Common patterns
        self.patterns = {
            'sequential_numbers': r'(012|123|234|345|456|567|678|789|890)',
            'sequential_letters': r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
            'keyboard_pattern': r'(qwerty|asdfgh|zxcvbn|qazwsx|!@#\$%\^)',
            'repeated_chars': r'(.)\1{2,}',
            'year_pattern': r'(19|20)\d{2}'
        }
        
        # Load breach database
        if use_comb_api:
            print("[INFO] Using COMB API for breach detection")
            self.compromised_hashes = set()
            self.breach_db_size = 3_200_000_000
        else:
            self.compromised_hashes = self._load_compromised_hashes(breach_file_path)
            self.breach_db_size = len(self.compromised_hashes)
            print(f"[INFO] Loaded {self.breach_db_size:,} compromised password hashes")
    
    def _load_compromised_hashes(self, breach_file_path: str = None) -> set:
        """Load hashes from breach database file or use small realistic default set"""
        compromised = set()
        
        if breach_file_path and os.path.exists(breach_file_path):
            print(f"[INFO] Loading breach database from: {breach_file_path}")
            try:
                with open(breach_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        password = line.strip()
                        if not password:
                            continue
                        if ':' in password:
                            password = password.split(':')[-1]
                        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
                        compromised.add(pwd_hash)
                print(f"[SUCCESS] Loaded {len(compromised):,} password hashes")
                return compromised
            except Exception as e:
                print(f"[ERROR] Failed to load breach file: {e}")

        # Use small default breach dataset (Top 50 real leaked passwords)
        print("[INFO] Using small default breach dataset")
        default_passwords = [
            '123456', 'password', '123456789', '12345678', 'qwerty', 'abc123',
            'football', 'iloveyou', 'admin', 'welcome', 'monkey', 'login',
            'princess', 'sunshine', 'passw0rd', 'password1', 'letmein',
            'dragon', 'admin123', 'root', 'hello123', 'trustno1', 'batman',
            'superman', 'charlie', 'shadow', 'master', 'internet', 'service',
            'secret', 'qwertyuiop', '1q2w3e4r', 'abc@123', 'zaq12wsx',
            'baseball', 'jordan23', 'iloveyou1', 'computer', 'daniel', 'jessica'
        ]
        
        for pwd in default_passwords:
            compromised.add(hashlib.sha256(pwd.encode()).hexdigest())
        
        return compromised

    def check_breach_comb_api(self, password: str) -> Tuple[bool, int]:
        """Check password using COMB API"""
        try:
            url = "https://api.proxynova.com/comb"
            params = {'query': password, 'start': 0, 'limit': 1}
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                count = data.get('count', 0)
                return (count > 0, count)
            return (False, 0)
        except:
            return (False, 0)

    def calculate_entropy(self, password: str) -> float:
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'[0-9]', password): charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password): charset_size += 32
        return len(password) * math.log2(charset_size) if charset_size else 0

    def estimate_crack_time(self, password: str) -> Dict[str, str]:
        entropy = self.calculate_entropy(password)
        # Use math.pow for better precision with large numbers
        combinations = math.pow(2, entropy)
        scenarios = {
            'online_throttled': 10,
            'online_unthrottled': 1000,
            'offline_slow': 1e9,
            'offline_fast': 1e11
        }
        return {name: self._format_time(combinations/speed) for name, speed in scenarios.items()}

    def _format_time(self, seconds: float) -> str:
        """Fixed time formatting with correct unit conversions"""
        if seconds < 0.001:
            return "Instant (< 0.001 seconds)"
        elif seconds < 1:
            return f"{seconds:.3f} seconds"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        
        minutes = seconds / 60
        if minutes < 60:
            return f"{minutes:.1f} minutes"
        
        hours = minutes / 60
        if hours < 24:
            return f"{hours:.1f} hours"
        
        days = hours / 24
        if days < 30:
            return f"{days:.1f} days"
        
        months = days / 30
        if months < 12:
            return f"{months:.1f} months"
        
        years = months / 12
        
        # Better formatting for extreme values
        if years < 1000:
            return f"{years:.1f} years"
        elif years < 1e6:
            return f"{years/1e3:.1f} thousand years"
        elif years < 1e9:
            return f"{years/1e6:.1f} million years"
        elif years < 1e12:
            return f"{years/1e9:.1f} billion years"
        elif years < 1e15:
            return f"{years/1e12:.1f} trillion years"
        elif years < 1e18:
            return f"{years/1e15:.1f} quadrillion years"
        elif years < 1e21:
            return f"{years/1e18:.1f} quintillion years"
        elif years < 1e24:
            return f"{years/1e21:.1f} sextillion years"
        else:
            # For extremely large numbers, show both readable and scientific notation
            return f"{years:.2e} years (effectively uncrackable)"

    def check_common_passwords(self, password: str) -> bool:
        return password.lower() in self.common_passwords

    def check_dictionary(self, password: str) -> List[str]:
        return [word for word in self.dictionary_words if word in password.lower()]

    def check_patterns(self, password: str) -> List[str]:
        return [name.replace('_', ' ') for name, pat in self.patterns.items()
                if re.search(pat, password.lower())]

    def check_breach_database(self, password: str) -> Tuple[bool, Optional[int]]:
        if self.use_comb_api:
            return self.check_breach_comb_api(password)
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        return (pwd_hash in self.compromised_hashes, None)

    def calculate_strength_score(self, password: str, is_breached: bool, patterns: List[str], dict_words: List[str]) -> Tuple[int, str]:
        score = 0
        length = len(password)

        # Length scoring
        if length >= 16: score += 35
        elif length >= 14: score += 30
        elif length >= 12: score += 25
        elif length >= 10: score += 20
        elif length >= 8: score += 12
        elif length >= 6: score += 5

        # Character diversity
        types = sum(bool(re.search(regex, password)) for regex in [r'[a-z]', r'[A-Z]', r'[0-9]', r'[^a-zA-Z0-9]'])
        score += types * 7.5

        # Entropy bonus
        entropy = self.calculate_entropy(password)
        score += min(25, int(entropy // 3))

        # Deductions
        if self.check_common_passwords(password): score -= 40
        if is_breached: score -= 30
        score -= len(patterns) * 8
        score -= len(dict_words) * 5

        score = max(0, min(100, score))

        rating_index = min(4, int(score // 20))
        rating = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][rating_index]

        return score, rating

    def analyze(self, password: str) -> Dict:
        if not password:
            return {"error": "Password cannot be empty"}
        
        is_common = self.check_common_passwords(password)
        is_breached, breach_count = self.check_breach_database(password)
        patterns = self.check_patterns(password)
        dict_words = self.check_dictionary(password)
        
        score, rating = self.calculate_strength_score(password, is_breached, patterns, dict_words)
        entropy = self.calculate_entropy(password)
        crack_times = self.estimate_crack_time(password)

        composition = {
            'length': len(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'[0-9]', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password))
        }
        
        recommendations = []
        if len(password) < 12: recommendations.append("Increase length to at least 12 characters")
        if not composition['has_uppercase']: recommendations.append("Add uppercase letters")
        if not composition['has_lowercase']: recommendations.append("Add lowercase letters")
        if not composition['has_digits']: recommendations.append("Add numbers")
        if not composition['has_special']: recommendations.append("Add special characters")
        if is_common: recommendations.append("CRITICAL: This is a commonly used password")
        if is_breached:
            recommendations.append("CRITICAL: This password appears in breach database")
        if patterns: recommendations.append(f"Avoid patterns: {', '.join(patterns)}")
        if dict_words: recommendations.append(f"Avoid dictionary words: {', '.join(dict_words)}")

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
        print(f"Common Password: {'YES ⚠️' if vuln['is_common_password'] else 'No'}")
        
        if vuln['found_in_breach']:
            print(f"Found in Breach: YES ⚠️")
        else:
            print("Found in Breach: No")
        
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
    print("1. Local Database")
    print("2. COMB API (Internet Required)")
    
    choice = input("\nSelect option (1 or 2) [default: 1]: ").strip() or "1"
    
    if choice == "2":
        analyzer = PasswordAnalyzer(use_comb_api=True)
    else:
        analyzer = PasswordAnalyzer()
    
    print("\n[INTERACTIVE MODE]")
    print("Enter 'quit' to exit\n")
    
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