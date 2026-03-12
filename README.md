# Cyberster Sensitive Info Scanner (C-SIS)

C-SIS is a professional, standalone CLI tool designed to recursively scan folders for sensitive information such as API keys, database connection strings, emails, and credentials.

## Features
- **Fast Recursive Scanning**: Scans `.txt`, `.py`, `.js`, `.html`, `.env`, `.json`, and `.md` files.
- **Regex-Based Detection**:
  - Google, AWS, and GitHub API Keys.
  - MongoDB and MySQL Connection Strings.
  - Emails and Hardcoded Passwords.
  - Private SSH Keys.
- **Professional UI**: Powered by `rich` with an Electric Blue and Cyan theme.
- **Progress Tracking**: Real-time progress bar while scanning.
- **Detailed Reporting**: Generates a clean markdown report (`scan_report.md`) after each scan.

## Installation

1. Ensure you have Python 3.10+ installed.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the tool by providing the path to the directory you want to scan:

```bash
python cyberster_scanner.py <folder_path>
```

### Example
```bash
python cyberster_scanner.py ./my_project
```

## Visuals
The tool features a high-end terminal interface with:
- ASCII Art Logo
- Electric Blue & Cyan color scheme
- Interactive Tables
- Status Bars

## Output
- **Console**: Displays a "Threats Found" table with file names, line numbers, and risk levels.
- **Report**: A comprehensive `scan_report.md` is generated in the root directory.

---
*Developed by Cyberster - Empowering Security.*
