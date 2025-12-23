#!/usr/bin/env python3
"""
Linux Hardening Audit Tool
Description:
This tool performs READ-ONLY security checks on a Linux system
based on basic CIS Linux Hardening Guidelines.
It does NOT modify any system configuration.
"""

import os
import subprocess
from datetime import datetime

# -----------------------------
# Helper function to run commands safely
# -----------------------------
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL)
        return result.decode().strip()
    except subprocess.CalledProcessError:
        return ""

# -----------------------------
# Audit checks
# -----------------------------
def check_firewall():
    status = run_command("ufw status")
    if "Status: active" in status:
        return True, "Firewall is enabled"
    return False, "Enable firewall using: sudo ufw enable"

def check_ssh_root_login():
    config = run_command("grep '^PermitRootLogin' /etc/ssh/sshd_config")
    if "no" in config:
        return True, "Root login is disabled"
    return False, "Set PermitRootLogin no in /etc/ssh/sshd_config"

def check_ssh_password_auth():
    config = run_command("grep '^PasswordAuthentication' /etc/ssh/sshd_config")
    if "no" in config:
        return True, "Password authentication is disabled"
    return False, "Disable password auth in sshd_config"

def check_passwd_permissions():
    perms = run_command("stat -c %a /etc/passwd")
    return perms == "644", "Correct permissions set" if perms == "644" else "Set permissions to 644"

def check_shadow_permissions():
    perms = run_command("stat -c %a /etc/shadow")
    return perms == "640", "Secure permissions applied" if perms == "640" else "Set permissions to 640"

def check_service(service):
    status = run_command(f"systemctl is-active {service}")
    if status != "active":
        return True, f"{service} service is not running"
    return False, f"Disable {service} service"

def check_auto_updates():
    status = run_command("dpkg -l unattended-upgrades")
    if "unattended-upgrades" in status:
        return True, "Automatic updates enabled"
    return False, "Enable unattended-upgrades"

# -----------------------------
# Main audit logic
# -----------------------------
def main():
    print("\n===== Linux Hardening Audit Report =====\n")

    audit_time = datetime.now()
    print(f"Audit Time: {audit_time}")
    print("Benchmark Reference: CIS Linux Hardening Guidelines\n")

    system_info = run_command("uname -a")
    print("System Information:")
    print(system_info)
    print("\n----------------------------------------\n")

    # Audit items: (Check Name, Function, Severity, Weight)
    checks = [
        ("Firewall Enabled", check_firewall, "High", 15),
        ("SSH Root Login Disabled", check_ssh_root_login, "High", 15),
        ("SSH Password Authentication Disabled", check_ssh_password_auth, "Medium", 10),
        ("/etc/passwd Permissions", check_passwd_permissions, "Low", 5),
        ("/etc/shadow Permissions", check_shadow_permissions, "Low", 5),
        ("TELNET Service Running", lambda: check_service("telnet"), "Low", 5),
        ("FTP Service Running", lambda: check_service("vsftpd"), "Low", 5),
        ("RSH Service Running", lambda: check_service("rsh"), "Low", 5),
        ("Automatic Updates Enabled", check_auto_updates, "Medium", 10),
    ]

    score = 0
    max_score = sum(item[3] for item in checks)

    risk_summary = {"High": 0, "Medium": 0, "Low": 0}

    report_lines = []
    report_lines.append("Linux Hardening Audit Report\n")
    report_lines.append(f"Audit Time: {audit_time}\n")
    report_lines.append("NOTE: This tool performs READ-ONLY security checks.\n\n")

    print("------- Audit Findings -------\n")

    for name, func, severity, weight in checks:
        result, recommendation = func()
        if result:
            score += weight
            status = "PASS"
        else:
            status = "FAIL"
            risk_summary[severity] += 1

        print(f"[{status}] {name} | Severity: {severity}")
        print(f" Recommendation: {recommendation}\n")

        report_lines.append(f"[{status}] {name} | Severity: {severity}\n")
        report_lines.append(f" Recommendation: {recommendation}\n\n")

    final_score = int((score / max_score) * 100)

    print("----------------------------------------")
    print(f"Final Security Score: {final_score} / 100\n")

    # Risk summary
    print("Risk Summary:")
    for level, count in risk_summary.items():
        print(f" {level} Risk Issues: {count}")

    report_lines.append("----------------------------------------\n")
    report_lines.append(f"Final Security Score: {final_score} / 100\n\n")
    report_lines.append("Risk Summary:\n")
    for level, count in risk_summary.items():
        report_lines.append(f"{level} Risk Issues: {count}\n")

    # Save report
    with open("audit_report.txt", "w") as file:
        file.writelines(report_lines)

    print("\nAudit report saved to audit_report.txt\n")

# -----------------------------
# Script entry point
# -----------------------------
if __name__ == "__main__":
    main()
