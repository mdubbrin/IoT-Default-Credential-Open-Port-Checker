## IoT Default Credential Open Port Checker

Scan a target list for common open ports and, when provided, expand the default-credential candidate set with an additional password wordlist.

### Usage

```bash
/usr/bin/python scanner.py targets.txt 2 --wordlist /path/to/wordlist.txt
```

The wordlist is optional. When omitted, the scanner uses only the built-in default credential list from `defaults.json`.
