import os
import re
import sys
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

import colorama
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

# Initialize Colorama for Windows terminal support
colorama.init()

# Custom Theme: Electric Blue and Cyan
CYBER_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "danger": "bold red",
    "success": "bold green",
    "brand": "bold royal_blue1",
    "accent": "bold cyan",
})

console = Console(theme=CYBER_THEME)

class CyberScanner:
    """
    Cyberster Sensitive Info Scanner (C-SIS) logic.
    """
    
    PATTERNS = {
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Access Key": r"aws_secret_access_key\s*[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]|(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
        "GitHub PAT": r"ghp_[0-9a-zA-Z]{36}",
        "GitHub OAuth": r"gho_[0-9a-zA-Z]{36}",
        "MongoDB URI": r"mongodb(?:\+srv)?:\/\/[^\s]+",
        "MySQL URI": r"mysql:\/\/[^\s]+",
        "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Hardcoded Password": r"(?i)(password|passwd|pwd|secret|key|token)\s*[:=]\s*['\"][^'\"]+['\"]",
        "Private SSH Key": r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----",
    }

    RISK_LEVELS = {
        "Google API Key": "High",
        "AWS Access Key ID": "High",
        "AWS Secret Access Key": "High",
        "GitHub PAT": "High",
        "GitHub OAuth": "High",
        "MongoDB URI": "High",
        "MySQL URI": "High",
        "Email Address": "Medium",
        "Hardcoded Password": "High",
        "Private SSH Key": "High",
    }

    EXTENSIONS = {".txt", ".py", ".js", ".html", ".env", ".json", ".md", ".key"}

    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.findings: List[Dict[str, Any]] = []

    def scan(self):
        """
        Recursively scans the directory for sensitive information.
        """
        files_to_scan = []
        for path in self.root_dir.rglob("*"):
            # Include files that match the extension OR are exactly '.env'
            if path.is_file() and (path.suffix.lower() in self.EXTENSIONS or path.name.lower() == ".env"):
                files_to_scan.append(path)

        if not files_to_scan:
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[accent]{task.description}"),
            BarColumn(bar_width=None, pulse_style="royal_blue1"),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning files...", total=len(files_to_scan))
            
            for file_path in files_to_scan:
                progress.update(task, description=f"Scanning {file_path.name}")
                self._scan_file(file_path)
                progress.advance(task)

    def _scan_file(self, file_path: Path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for line_num, content in enumerate(lines, 1):
                    for name, pattern in self.PATTERNS.items():
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            self.findings.append({
                                "file": str(file_path.relative_to(self.root_dir)),
                                "line": line_num,
                                "type": name,
                                "risk": self.RISK_LEVELS.get(name, "Medium"),
                                "content": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0)
                            })
        except Exception as e:
            console.print(f"[danger]Error reading {file_path}: {e}[/danger]")

    def generate_report(self, output_file: str = "scan_report.md"):
        """
        Generates a markdown report.
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# CYBERSTER Sensitive Info Scan Report\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Scan Directory:** `{self.root_dir.absolute()}`\n\n")
            f.write(f"**Total Threats Found:** {len(self.findings)}\n\n")
            
            if not self.findings:
                f.write("## No threats found. Great job!\n")
                return

            f.write("| File Name | Line | Threat Type | Risk Level |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            for finding in self.findings:
                f.write(f"| {finding['file']} | {finding['line']} | {finding['type']} | {finding['risk']} |\n")
            
            f.write("\n\n---\n*Report generated by C-SIS tool.*")

def print_header():
    ascii_art = """
   ______     ______  ______  ______  ______  ______  ______  ______  ______    
  /      \   /      \/      \/      \/      \/      \/      \/      \/      \   
 |  $$$$$$\ |  $$$$$$|  $$$$$$|  $$$$$$|  $$$$$$|  $$$$$$|  $$$$$$|  $$$$$$|  $$$$$$\  
 | $$   \$$ | $$__| $$ $$  | $$ $$  | $$ $$__| $$ $$  | $$ $$  | $$ $$__| $$ $$__| $$ 
 | $$       | $$    $$ $$  | $$ $$  | $$ $$    $$ $$  | $$ $$  | $$ $$    $$ $$    $$ 
 | $$   __  | $$$$$$$$ $$  | $$ $$  | $$ $$$$$$$$ $$  | $$ $$  | $$ $$$$$$$$ $$$$$$$$ 
 | $$__/  \ | $$  | $$ $$__/ $$ $$__/ $$ $$  | $$ $$__/ $$ $$__/ $$ $$  | $$ $$  | $$ 
  \$$    $$ | $$  | $$|      $$|      $$| $$  | $$|      $$|      $$| $$  | $$| $$  | $$ 
   \$$$$$$  |__/  |__/ \$$$$$$  \$$$$$$ |__/  |__/ \$$$$$$  \$$$$$$ |__/  |__/|__/  |__/ 
    """
    
    # Simpler ASCII for "CYBERSTER" to ensure it looks good
    cyberster_logo = """
   ____ ___  ____  _____ ____  ____ _____ _____ ____  
  / ___/ _ \|  _ \| ____|  _ \/ ___|_   _| ____|  _ \ 
 | |  | | | | | | |  _| | |_) \___ \ | | |  _| | |_) |
 | |__| |_| | |_| | |___|  _ < ___) || | | |___|  _ < 
  \____\___/|____/|_____|_| \_\____/ |_| |_____|_| \_\\
    """
    
    console.print(Panel(Text(cyberster_logo, style="brand"), subtitle="Sensitive Info Scanner (C-SIS)", subtitle_align="right", border_style="accent"))

def main():
    if len(sys.argv) < 2:
        print_header()
        console.print("[warning]Usage: python cyberster_scanner.py <folder_path>[/warning]")
        return

    target_path = sys.argv[1]
    if not os.path.isdir(target_path):
        console.print(f"[danger]Error: {target_path} is not a valid directory.[/danger]")
        return

    print_header()
    console.print(f"[info]Starting scan in:[/info] [accent]{target_path}[/accent]\n")

    scanner = CyberScanner(target_path)
    scanner.scan()

    # Display Findings Table
    if scanner.findings:
        table = Table(title="Threats Found", border_style="accent", header_style="accent", show_lines=True)
        table.add_column("File Name", style="info")
        table.add_column("Line", justify="right", style="accent")
        table.add_column("Threat Type", style="warning")
        table.add_column("Risk Level", style="danger")

        for finding in scanner.findings:
            risk_style = "danger" if finding["risk"] == "High" else "warning"
            table.add_row(
                finding["file"],
                str(finding["line"]),
                finding["type"],
                finding["risk"]
            )
        
        console.print("\n")
        console.print(table)
        
        scanner.generate_report()
        console.print(f"\n[success]Scan complete! Report generated: [accent]scan_report.md[/accent][/success]")
    else:
        console.print("\n[success]No threats detected. Your files are clean![/success]")

if __name__ == "__main__":
    main()
