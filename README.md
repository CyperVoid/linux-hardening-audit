# Linux Hardening Audit Tool

A Python-based Linux security auditing tool that evaluates system configurations against **CIS (Center for Internet Security) Linux Hardening Guidelines**.  
The tool performs a **read-only security assessment** and generates a detailed audit report with severity levels, recommendations, and a final security score.

---

##  Objective
The objective of this project is to:
- Identify common Linux security misconfigurations
- Evaluate system hardening status using CIS benchmarks
- Generate an audit report with actionable recommendations
- Help learners understand real-world Linux security auditing

---

##  Tools & Technologies
- **Operating System:** Kali Linux
- **Language:** Python 3
- **Benchmark:** CIS Linux Hardening Guidelines
- **Libraries Used:**
  - os
  - subprocess
  - platform
  - datetime

---

##  Features
- Firewall configuration check (UFW)
- SSH hardening checks (root login & password authentication)
- Sensitive file permission validation
- Detection of insecure services (Telnet, FTP, RSH)
- Automatic update configuration check
- Severity-based risk classification
- Final security score calculation
- Text-based audit report generation

---

##  Methodology
1. Collect system and OS information  
2. Perform security checks without modifying system settings  
3. Classify findings as **PASS / FAIL**  
4. Assign severity levels (High / Medium / Low)  
5. Calculate an overall security score  
6. Generate an audit report with recommendations  

---

##  How to Run

The project was developed and tested on Kali Linux using Python 3.

First, verify that Python 3 is installed:

    python3 --version

If Python 3 is not available, install it using:

    sudo apt update
    sudo apt install python3

Create a project directory and navigate into it:

    mkdir linux-hardening-audit
    cd linux-hardening-audit

Create the Python file for the audit tool:

    nano linux_hardening_audit.py

Paste the complete source code into the file and save it. Then run the tool using:

    python3 linux_hardening_audit.py

The tool checks firewall status, SSH configuration, sensitive file permissions, presence of insecure services, and automatic update settings. It displays PASS/FAIL results with severity levels, provides security recommendations, calculates an overall security score, and saves the output to an audit report file.

A low score is expected on Kali Linux, as it is designed for penetration testing rather than system hardening. The tool is safe to run, requires no root access, and makes no changes to the system.



