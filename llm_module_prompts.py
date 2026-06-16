MODULE_PROMPTS = {

"network_scanner": """
Explain the port scanning result.

Include:
- which ports are open
- what services those ports run
- security risks of open ports
- recommended mitigation
""",

"password_analyzer": """
Explain the password strength analysis.

Include:
- entropy meaning
- brute-force resistance
- how attackers crack weak passwords
- recommendations for stronger passwords
""",

"file_integrity": """
Explain the file integrity monitoring result.

Include:
- meaning of modified/missing/new files
- why attackers change system files
- how integrity monitoring helps detect intrusions
""",

"log_defender": """
Explain the log analysis result.

Include:
- brute-force attack detection
- failed login attempts pattern
- attacker behavior indicators
""",

"crypto_lab": """
Explain the cryptographic operation.

Include:
- difference between encoding, hashing, and encryption
- security implications of chosen algorithm
""",

"cvss": """
Explain the CVSS vulnerability score.

Include:
- meaning of each metric
- why the vulnerability severity is classified this way
- potential security impact
""",

"jwt_analyzer": """
Explain the JWT security analysis.

Include:
- algorithm used
- token expiration
- security risks such as alg=none or exposed payload
""",

"classical_cipher": """
Explain the classical cipher result.

Include:
- how the cipher works
- why classical ciphers are insecure today
- how modern cryptography differs
""",

"subnet_calculator": """
Explain the subnet calculation result.

Include:
- network address
- broadcast address
- host capacity
- how subnetting improves network security
""",

"http_headers": """
Explain the HTTP header security analysis.

Include:
- missing security headers
- risks like XSS, clickjacking, MIME sniffing
- recommended secure configurations
""",

"metadata": """
Explain the metadata analysis result.

Include:
- device information leakage
- GPS location risks
- OSINT implications
""",

"xss_simulator": """
Explain the XSS payload analysis.

Include:
- how XSS attacks work
- why the payload is dangerous
- mitigation techniques
""",

"url_detector": """
Explain the phishing URL risk assessment.

Include:
- suspicious domain patterns
- entropy and randomness
- phishing techniques used
""",

"digital_signature": """
Explain the digital signature verification result.

Include:
- integrity verification
- authentication
- how public key cryptography works
""",

"firewall": """
Explain the firewall rule evaluation.

Include:
- rule matching logic
- why packet was allowed or blocked
- firewall best practices
""",

"password_storage": """
Explain the secure password storage demonstration.

Include:
- why salting is important
- rainbow table attacks
- why bcrypt/argon2 are recommended
"""
}