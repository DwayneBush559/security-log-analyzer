import unittest

from analyzer import analyze_lines


class AnalyzerTests(unittest.TestCase):
    def test_detects_injection(self):
        findings = analyze_lines(
            ["10.0.0.5 GET /?id=1 UNION SELECT password FROM users"]
        )
        self.assertTrue(any(item.rule == "sql_injection" for item in findings))

    def test_detects_brute_force_pattern(self):
        lines = [
            "192.168.1.8 failed login user=a",
            "192.168.1.8 failed login user=a",
            "192.168.1.8 authentication failed user=a",
        ]
        findings = analyze_lines(lines)
        self.assertTrue(any(item.rule == "possible_brute_force" for item in findings))

    def test_clean_line_has_no_finding(self):
        self.assertEqual(analyze_lines(["10.0.0.2 GET /health 200"]), [])


if __name__ == "__main__":
    unittest.main()
