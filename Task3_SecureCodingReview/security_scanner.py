import re
import sys
from datetime import datetime

VULNERABILITY_RULES = [
    {
        "id": "V001",
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "pattern": r"(f['\"].*SELECT.*\{|execute\(f['\"]|format\(.*SELECT)",
        "description": "User input is directly embedded into SQL queries.",
        "recommendation": "Use parameterized queries: conn.execute('SELECT * FROM users WHERE username=?', (username,))"
    },
    {
        "id": "V002",
        "name": "Hardcoded Credentials",
        "severity": "HIGH",
        "pattern": r"(PASSWORD\s*=\s*['\"][^'\"]+['\"]|SECRET_KEY\s*=\s*['\"][^'\"]+['\"]|ADMIN_PASS\s*=\s*['\"][^'\"]+['\"])",
        "description": "Passwords or secrets are hardcoded in source code.",
        "recommendation": "Use environment variables: os.environ.get('SECRET_KEY')"
    },
    {
        "id": "V003",
        "name": "Weak Hashing Algorithm (MD5)",
        "severity": "HIGH",
        "pattern": r"hashlib\.md5|hashlib\.sha1",
        "description": "MD5/SHA1 are cryptographically broken for password storage.",
        "recommendation": "Use bcrypt: bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
    },
    {
        "id": "V004",
        "name": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "pattern": r"return\s+f['\"].*<.*\{",
        "description": "User input is rendered directly into HTML without escaping.",
        "recommendation": "Use Jinja2 templates with auto-escaping or markupsafe.escape()"
    },
    {
        "id": "V005",
        "name": "Path Traversal",
        "severity": "CRITICAL",
        "pattern": r"os\.path\.join.*request\.",
        "description": "User-controlled input used in file paths.",
        "recommendation": "Use os.path.basename() and validate against a whitelist of allowed files."
    },
    {
        "id": "V006",
        "name": "Debug Mode Enabled",
        "severity": "MEDIUM",
        "pattern": r"app\.run\(.*debug\s*=\s*True",
        "description": "Flask debug mode exposes interactive debugger to attackers.",
        "recommendation": "Set debug=False or use environment variable: debug=os.environ.get('DEBUG', False)"
    },
    {
        "id": "V007",
        "name": "Sensitive Data Exposure",
        "severity": "HIGH",
        "pattern": r"SELECT \* FROM users",
        "description": "All user data including passwords is returned with no authentication.",
        "recommendation": "Add authentication checks and never return raw password data."
    },
]

SEVERITY_ICONS = {
    "CRITICAL": "[CRITICAL]",
    "HIGH":     "[HIGH]   ",
    "MEDIUM":   "[MEDIUM] ",
    "LOW":      "[LOW]    "
}

def scan_file(filepath):
    print("\n" + "="*60)
    print("   CodeAlpha - Secure Code Scanner")
    print(f"   File   : {filepath}")
    print(f"   Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

    try:
        with open(filepath, "r") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        print(f"ERROR: File not found: {filepath}")
        return

    findings = []

    for rule in VULNERABILITY_RULES:
        matches = [
            (i + 1, line.strip())
            for i, line in enumerate(lines)
            if re.search(rule["pattern"], line, re.IGNORECASE)
        ]
        if matches:
            findings.append({"rule": rule, "matches": matches})

    if not findings:
        print("No vulnerabilities detected!\n")
        return

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["rule"]["severity"], 99))

    print(f"Found {len(findings)} vulnerability/vulnerabilities:\n")
    print("-" * 60)

    for i, finding in enumerate(findings, 1):
        rule = finding["rule"]
        icon = SEVERITY_ICONS.get(rule["severity"], "")
        print(f"\n[{i}] {icon} {rule['name']} ({rule['id']})")
        print(f"    Description    : {rule['description']}")
        print(f"    Recommendation : {rule['recommendation']}")
        print(f"    Found on line(s):")
        for lineno, code in finding["matches"]:
            print(f"       Line {lineno}: {code}")

    print("\n" + "="*60)
    critical = sum(1 for f in findings if f["rule"]["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["rule"]["severity"] == "HIGH")
    medium   = sum(1 for f in findings if f["rule"]["severity"] == "MEDIUM")
    print(f"  SUMMARY: {len(findings)} issues found")
    print(f"  CRITICAL : {critical}")
    print(f"  HIGH     : {high}")
    print(f"  MEDIUM   : {medium}")
    print("="*60 + "\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "vulnerable_app.py"
    scan_file(target)