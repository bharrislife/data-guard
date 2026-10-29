import re
import json
import sys

class DataGuard:
    def __init__(self):
        # Regular expressions for common sensitive data patterns
        self.patterns = {
            "EMAIL": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            "PHONE": r'\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b',
            "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
            "API_KEY": r'(?i)(api[_-]?key|secret|token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'
        }

    def mask_text(self, text: str) -> str:
        """Masks detected sensitive information in a raw text string."""
        masked_text = text
        for label, pattern in self.patterns.items():
            if label == "API_KEY":
                masked_text = re.sub(pattern, r'\1: [REDACTED_API_KEY]', masked_text)
            else:
                masked_text = re.sub(pattern, f"[REDACTED_{label}]", masked_text)
        return masked_text

    def sanitize_record(self, record: dict) -> dict:
        """Recursively sanitizes dictionary data."""
        sanitized = {}
        for key, value in record.items():
            if isinstance(value, str):
                sanitized[key] = self.mask_text(value)
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_record(value)
            elif isinstance(value, list):
                sanitized[key] = [self.mask_text(v) if isinstance(v, str) else v for v in value]
            else:
                sanitized[key] = value
        return sanitized

if __name__ == "__main__":
    guard = DataGuard()
    
    # Sample dirty payload simulating internal company logging/data dump
    sample_data = {
        "user_id": 10482,
        "contact_info": {
            "email": "john.doe@example.com",
            "phone": "555-867-5309",
            "ssn": "000-12-3456"
        },
        "config": {
            "api_key": "sk_live_998877665544332211"
        },
        "notes": "User requested support via john.doe@example.com regarding phone line 555-867-5309."
    }

    print("\n--- ORIGINAL PAYLOAD ---")
    print(json.dumps(sample_data, indent=2))

    sanitized_data = guard.sanitize_record(sample_data)

    print("\n--- SANITIZED / MASKED PAYLOAD ---")
    print(json.dumps(sanitized_data, indent=2))
