# Data Guard

`data-guard` is a lightweight, high-performance Python security utility designed to sanitize, mask, and redact sensitive personal data (PII) and credentials from structured payloads before transmitting them to LLMs or third-party APIs.

## Features
- **Pattern-Based Redaction:** Automatically detects and redacts emails, phone numbers, and Social Security Numbers (SSNs) using optimized regular expressions.
- **Key-Aware Dictionary Sanitization:** Inspects nested dictionary keys to sanitize explicit credentials (`api_key`, `secret`, `token`, `password`) regardless of format.
- **Recursive Processing:** Traverses deeply nested JSON and Python dictionary data structures.

## Installation & Usage

1. Clone the repository:
   ```bash
   git clone [https://github.com/bharrislife/data-guard.git](https://github.com/bharrislife/data-guard.git)
   cd data-guard
