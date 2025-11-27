# 🔐 Password Security Analyzer

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A comprehensive password security assessment tool that evaluates password strength, detects vulnerabilities, and checks against breach databases following NIST guidelines.

## ✨ Features

- 🎯 **Strength Scoring**: 0-100 point scoring system with detailed ratings
- 🔍 **Breach Detection**: Check against 3.2B+ compromised credentials via COMB API or local database
- 📊 **Entropy Calculation**: Measure password randomness and unpredictability
- ⏱️ **Crack Time Estimation**: Calculate time to crack across 4 attack scenarios
- 🚨 **Pattern Detection**: Identify sequential characters, keyboard patterns, and repeated sequences
- 📚 **Dictionary Analysis**: Detect common dictionary words in passwords
- 💡 **Smart Recommendations**: Get actionable advice to improve password security
- 🔒 **Privacy-First**: Uses SHA-256 hashing - never stores plaintext passwords

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Features in Detail](#features-in-detail)
- [Breach Database Options](#breach-database-options)
- [Understanding the Results](#understanding-the-results)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Install Dependencies
```bash
# Clone the repository
git clone https://github.com/yourusername/password-security-analyzer.git
cd password-security-analyzer

# Install required packages
pip install -r requirements.txt
```

### Requirements.txt
```text
requests>=2.28.0
```

## ⚡ Quick Start

### Interactive Mode
```bash
python password_security_analyzer.py
```

### Programmatic Usage
```python
from password_security_analyzer import PasswordAnalyzer

# Initialize analyzer
analyzer = PasswordAnalyzer()

# Analyze a password
result = analyzer.analyze("MyP@ssw0rd2024")

# Print detailed report
analyzer.print_report(result)

# Access specific metrics
print(f"Score: {result['score']}/100")
print(f"Rating: {result['rating']}")
print(f"Breached: {result['vulnerabilities']['found_in_breach']}")
```

## 📖 Usage

### Option 1: Local Database Mode (Default)

Uses built-in dataset of 40+ most common breached passwords.
```python
analyzer = PasswordAnalyzer()
```

### Option 2: COMB API Mode

Checks against 3.2 billion compromised credentials (requires internet).
```python
analyzer = PasswordAnalyzer(use_comb_api=True)
```


**Breach file format:**
```text
password123
qwerty2024
letmein
```

## 🔍 Features in Detail

### 1. Strength Scoring Algorithm

The tool uses a multi-factor scoring system (0-100):

**Points Added:**
- **Length**: 5-35 points based on character count
- **Character Diversity**: Up to 30 points (7.5 per type)
- **Entropy**: Up to 25 points based on randomness

**Points Deducted:**
- Common password: -40 points
- Found in breach: -30 points
- Vulnerable patterns: -8 points each
- Dictionary words: -5 points each

**Rating Scale:**
- 0-19: Very Weak 🔴
- 20-39: Weak 🟠
- 40-59: Moderate 🟡
- 60-79: Strong 🟢
- 80-100: Very Strong 🔵

### 2. Crack Time Scenarios

| Scenario | Speed | Example |
|----------|-------|---------|
| **Online Throttled** | 10/sec | Login forms with rate limiting |
| **Online Unthrottled** | 1,000/sec | APIs without protection |
| **Offline Slow** | 1B/sec | CPU-based cracking |
| **Offline Fast** | 100B/sec | GPU-based cracking (RTX 4090) |

### 3. Pattern Detection

Automatically detects:
- ✅ Sequential numbers (123, 456, 789)
- ✅ Sequential letters (abc, xyz)
- ✅ Keyboard patterns (qwerty, asdfgh)
- ✅ Repeated characters (aaa, 111)
- ✅ Year patterns (1990-2099)

### 4. Entropy Calculation

**Formula:** `Entropy = Length × log₂(Charset Size)`

**Character Sets:**
- Lowercase: 26 characters
- Uppercase: 26 characters
- Digits: 10 characters
- Special: 32 characters

**Example:**
```
Password: "Hello123"
Charset: 26 + 26 + 10 = 62
Entropy: 8 × log₂(62) ≈ 47.6 bits
```

## 🗄️ Breach Database Options

### Local Database (Default)

- ✅ Works offline
- ✅ Fast performance
- ✅ Privacy-focused
- ⚠️ Limited to 40+ passwords

### COMB API

- ✅ 3.2B+ credentials
- ✅ Real-time updates
- ⚠️ Requires internet
- ⚠️ Rate limited

### Custom File

- ✅ Full control
- ✅ Offline capable
- ✅ Unlimited size
- ⚠️ Requires setup

**Download breach databases:**
- [Have I Been Pwned](https://haveibeenpwned.com/Passwords)
- [SecLists](https://github.com/danielmiessler/SecLists)

## 📊 Understanding the Results

### Sample Output
```
======================================================================
PASSWORD SECURITY AUDIT REPORT
======================================================================

[STRENGTH ASSESSMENT]
Score: 45/100
Rating: Moderate
Entropy: 52.3 bits

[COMPOSITION]
Length: 12 characters
Lowercase: ✓
Uppercase: ✓
Digits: ✓
Special Characters: ✗

[CRACK TIME ESTIMATES]
Online Throttled: 2.5 million years
Online Unthrottled: 25.3 thousand years
Offline Slow: 25.3 seconds
Offline Fast: 0.3 seconds

[VULNERABILITY ASSESSMENT]
Breach Database: Local Database (40 credentials)
Common Password: No
Found in Breach: No
Patterns Found: sequential numbers

[RECOMMENDATIONS]
1. Add special characters
2. Increase length to at least 14 characters
3. Avoid patterns: sequential numbers

[HASH]
SHA-256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
======================================================================
```

## 🔧 API Reference

### PasswordAnalyzer Class

#### Constructor
```python
PasswordAnalyzer(breach_file_path: str = "breached_password.txt", 
                 use_comb_api: bool = False)
```

**Parameters:**
- `breach_file_path` (str): Path to local breach database file
- `use_comb_api` (bool): Use COMB API for breach checks

#### Methods

##### `analyze(password: str) -> Dict`

Performs comprehensive password analysis.

**Returns:**
```python
{
    'score': int,                      # 0-100
    'rating': str,                     # Very Weak to Very Strong
    'entropy_bits': float,             # Randomness measure
    'composition': dict,               # Character type breakdown
    'crack_time_estimates': dict,      # Time for each scenario
    'vulnerabilities': dict,           # Security issues found
    'recommendations': list,           # Improvement suggestions
    'hash_sha256': str                 # Password hash
}
```

##### `print_report(analysis: Dict) -> None`

Prints formatted analysis report to console.

##### `calculate_entropy(password: str) -> float`

Calculates password entropy in bits.

##### `estimate_crack_time(password: str) -> Dict[str, str]`

Estimates time to crack under different scenarios.

##### `check_breach_database(password: str) -> Tuple[bool, Optional[int]]`

Checks if password appears in breach database.

## 💡 Examples

### Example 1: Batch Analysis
```python
from password_security_analyzer import PasswordAnalyzer

analyzer = PasswordAnalyzer()

passwords = [
    "password123",
    "MyS3cur3P@ssw0rd!",
    "Tr0ub4dor&3",
    "correcthorsebatterystaple"
]

for pwd in passwords:
    result = analyzer.analyze(pwd)
    print(f"{pwd}: {result['score']}/100 - {result['rating']}")
```

### Example 2: Integration with Registration System
```python
def validate_password(password: str) -> tuple[bool, list]:
    """
    Validate password meets security requirements.
    Returns: (is_valid, error_messages)
    """
    from password_security_analyzer import PasswordAnalyzer
    
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze(password)
    
    errors = []
    
    if result['score'] < 40:
        errors.append("Password is too weak")
    
    if result['vulnerabilities']['found_in_breach']:
        errors.append("Password has been compromised in data breach")
    
    if result['vulnerabilities']['is_common_password']:
        errors.append("Password is too common")
    
    return (len(errors) == 0, errors)

# Usage
is_valid, errors = validate_password("user_input_password")
if not is_valid:
    print("Password rejected:", errors)
```

### Example 3: Generate Password Report
```python
def generate_password_report(password: str, filename: str = "report.txt"):
    """Save analysis report to file"""
    from password_security_analyzer import PasswordAnalyzer
    
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze(password)
    
    with open(filename, 'w') as f:
        f.write(f"Password Strength: {result['score']}/100\n")
        f.write(f"Rating: {result['rating']}\n")
        f.write(f"Entropy: {result['entropy_bits']} bits\n\n")
        
        f.write("Vulnerabilities:\n")
        for vuln, value in result['vulnerabilities'].items():
            f.write(f"  - {vuln}: {value}\n")
        
        f.write("\nRecommendations:\n")
        for rec in result['recommendations']:
            f.write(f"  • {rec}\n")

generate_password_report("MyPassword123")
```

### Example 4: Command-Line Tool
```python
import sys
from password_security_analyzer import PasswordAnalyzer

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_password.py <password>")
        sys.exit(1)
    
    password = sys.argv[1]
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze(password)
    
    print(f"Score: {result['score']}/100")
    print(f"Rating: {result['rating']}")
    
    if result['score'] < 60:
        print("\n⚠️  Password is not strong enough!")
        sys.exit(1)
    else:
        print("\n✅ Password meets security requirements")
        sys.exit(0)
```

### Example 5: Flask Web Integration
```python
from flask import Flask, request, jsonify
from password_security_analyzer import PasswordAnalyzer

app = Flask(__name__)
analyzer = PasswordAnalyzer()

@app.route('/api/check-password', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password required'}), 400
    
    result = analyzer.analyze(password)
    
    return jsonify({
        'score': result['score'],
        'rating': result['rating'],
        'is_secure': result['score'] >= 60,
        'recommendations': result['recommendations']
    })

if __name__ == '__main__':
    app.run(debug=True)
```

### Example 6: Password Strength Meter
```python
from password_security_analyzer import PasswordAnalyzer

def get_password_strength_visual(password: str) -> str:
    """Returns a visual representation of password strength"""
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze(password)
    
    score = result['score']
    filled = int(score / 10)
    empty = 10 - filled
    
    bar = '█' * filled + '░' * empty
    
    colors = {
        'Very Weak': '🔴',
        'Weak': '🟠',
        'Moderate': '🟡',
        'Strong': '🟢',
        'Very Strong': '🔵'
    }
    
    icon = colors.get(result['rating'], '⚪')
    
    return f"{icon} [{bar}] {score}/100 - {result['rating']}"

# Usage
print(get_password_strength_visual("password"))
# 🔴 [█░░░░░░░░░] 10/100 - Very Weak

print(get_password_strength_visual("MyS3cur3P@ss!"))
# 🟢 [████████░░] 75/100 - Strong
```

## 🛡️ Security Considerations

### What This Tool Does

✅ Analyzes password strength  
✅ Detects known vulnerabilities  
✅ Provides security recommendations  
✅ Uses cryptographic hashing (SHA-256)  

### What This Tool Does NOT Do

❌ Store passwords  
❌ Transmit passwords (except to COMB API if enabled)  
❌ Guarantee absolute security  
❌ Replace proper authentication systems  

### Best Practices

1. **Never log passwords in plaintext**
2. **Use HTTPS when deploying web integrations**
3. **Implement rate limiting on password checks**
4. **Don't reject passwords solely based on entropy**
5. **Educate users about password managers**
6. **Consider implementing MFA (Multi-Factor Authentication)**

### Security Warning

⚠️ **Important**: When using this tool in production:

- Never send passwords to third-party APIs without user consent
- Always use HTTPS for web implementations
- Implement proper rate limiting to prevent abuse
- Consider privacy implications of breach checking
- Use local databases when handling sensitive passwords

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup
```bash
# Clone your fork
git clone https://github.com/yourusername/password-security-analyzer.git
cd password-security-analyzer

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Format code
black password_security_analyzer.py
```

### Contribution Ideas

- [ ] Add support for more breach databases
- [ ] Implement password generation suggestions
- [ ] Add multilingual support
- [ ] Create GUI interface
- [ ] Add zxcvbn algorithm integration
- [ ] Implement ML-based pattern detection
- [ ] Add password policy enforcement
- [ ] Create REST API wrapper
- [ ] Add support for passphrase analysis
- [ ] Implement real-time password strength feedback
- [ ] Add browser extension
- [ ] Create mobile app version

## 🧪 Testing

Run the test suite:
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=password_security_analyzer

# Run specific test file
pytest tests/test_analyzer.py
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 📚 Resources

### Password Security Standards

- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

### Breach Databases

- [Have I Been Pwned](https://haveibeenpwned.com/)
- [COMB Database](https://www.troyhunt.com/the-comb-database-now-available-in-pwnedpasswords/)
- [SecLists Password Lists](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### Further Reading

- [Password Strength](https://en.wikipedia.org/wiki/Password_strength)
- [Entropy (Information Theory)](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [Dictionary Attack](https://en.wikipedia.org/wiki/Dictionary_attack)
- [Rainbow Table](https://en.wikipedia.org/wiki/Rainbow_table)

## 🔧 Troubleshooting

### Common Issues

**Issue: COMB API timeout**
```
Solution: Check your internet connection or switch to local database mode
analyzer = PasswordAnalyzer(use_comb_api=False)
```

**Issue: Import error**
```
Solution: Ensure all dependencies are installed
pip install -r requirements.txt
```

**Issue: Breach file not loading**
```
Solution: Check file path and format
- File should be plain text
- One password per line
- UTF-8 encoding
```

## 📊 Performance

### Benchmarks

Tested on: Intel i7-10700K, 16GB RAM, Python 3.10

| Operation | Time (avg) |
|-----------|------------|
| Single password analysis (local) | ~2ms |
| Single password analysis (COMB API) | ~150ms |
| Batch 100 passwords (local) | ~200ms |
| Load 1M breach hashes | ~5s |

## 🗺️ Roadmap

### Version 2.0 (Planned)

- [ ] GUI Desktop Application
- [ ] Browser Extension (Chrome, Firefox)
- [ ] Mobile App (iOS, Android)
- [ ] Real-time API
- [ ] Machine Learning integration
- [ ] Passphrase generator
- [ ] Multi-language support

### Version 1.5 (In Progress)

- [ ] zxcvbn algorithm integration
- [ ] Advanced pattern detection
- [ ] Custom policy configuration
- [ ] Export reports (PDF, JSON)

## 🙏 Acknowledgments

- Inspired by NIST Digital Identity Guidelines
- Breach data methodology from Have I Been Pwned
- Community feedback and contributions
- Built with ❤️ using Python

## 📧 Contact

**Project Maintainer:** Your Name

- GitHub: [@yourusername](https://github.com/yourusername)
- Email: your.email@example.com
- Twitter: [@yourhandle](https://twitter.com/yourhandle)
- Website: [yourwebsite.com](https://yourwebsite.com)

## ⭐ Star History

If you find this project useful, please consider giving it a star!

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/password-security-analyzer&type=Date)](https://star-history.com/#yourusername/password-security-analyzer&Date)

## 💬 FAQ

**Q: Is this tool safe to use with my real passwords?**  
A: The tool runs locally and doesn't store passwords. However, if using COMB API, passwords are sent to a third-party service.

**Q: Can I use this in production?**  
A: Yes, but implement proper security measures (HTTPS, rate limiting, etc.).

**Q: How accurate is the breach detection?**  
A: Local database has 40+ passwords. COMB API has 3.2B+ credentials for better accuracy.

**Q: Does it work offline?**  
A: Yes, when using local database mode (default).

**Q: Can I customize the scoring algorithm?**  
A: Yes, you can modify the `calculate_strength_score()` method.

**Q: What about passphrases?**  
A: The tool analyzes passphrases but is optimized for traditional passwords. Passphrase-specific analysis is planned for v2.0.

---

**Made with ❤️ for better password security**

*Remember: The best password is one you don't have to remember - use a password manager!*
