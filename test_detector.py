from detector import analyze_url

tests = [
    ("https://example.com", "LOW"),
    ("http://192.168.1.100/login/verify", "HIGH"),
    ("http://example.com/verify-account-login", "SUSPICIOUS"),
    ("http://paypal-secure-login.com/update", "HIGH"),
    ("http://free-bonus-claim.tk/reward", "HIGH"),
]

print("=== TEST RESULTS ===")
all_pass = True
for url, expected in tests:
    r = analyze_url(url)
    level = r["risk_level"]
    score = r["risk_score"]
    status = "PASS" if level == expected else "FAIL (expected {})".format(expected)
    if level != expected:
        all_pass = False
    print("{:<6}  Score:{:>3}/100  Level:{:<11}  {}".format(status, score, level, url[:55]))

print()
print("All tests passed!" if all_pass else "Some tests failed.")
