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

## ▶️ How to Run
```bash
python3 linux_hardening_audit.py

