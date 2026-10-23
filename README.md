
# Security Log Analyzer

A Python cybersecurity tool that analyzes simulated login logs
and detects potentially suspicious login patterns.

## Features

- Counts failed login attempts by username and IP address.
- Detects repeated failed logins.
- Flags IP addresses targeting multiple accounts.
- Uses configurable detection thresholds.

## Requirements

- Python 3

## Run the Project

```bash
python3 analyzer.py
```

## Project Structure

- `analyzer.py`: Main detection logic.
- `sample_logs.txt`: Simulated login records.
- `.gitignore`: Excludes unnecessary or sensitive files.

## Limitations

This is a rule-based demonstration, not a production security
system. Alerts indicate suspicious patterns, not confirmed attacks.

## Future Improvements

- Automated tests.
- Time-window-based detection.
- Security reports.
- Machine learning-based intrusion detection.
