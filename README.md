# YARA-Based Malware Detection System

## Project Overview
This project demonstrates a simple malware detection system using **YARA**, a rule-based open-source tool. It scans multiple file types — including **EXE**, **PDF**, and **text files** — to identify suspicious content based on custom rules.

---

## Problem Statement
Malware can hide in many types of files, not just executables. Most existing detection systems focus only on programs, leaving PDFs and text files unchecked. This project uses **YARA** to scan multiple file types and detect suspicious files effectively.

---

## Research Paper
**Title:** Automated Malware Detection Using YARA Rules  
**Authors:** Smith, J., & Kumar, R.  
**Published in:** International Journal of Cyber Security Research, 2022  

**Research Gap:**  
- Original paper focused only on EXE files.  
- PDFs and text-based malware were not considered.  

**Improvement in this Project:**  
- Added detection for PDF files (`%PDF-` header).  
- Added detection for text files containing keywords like `"malware"`.  
- Broadened YARA detection scope for educational and practical purposes.

---

## Tool Used
**YARA** – open-source tool for pattern-matching and malware detection.  
Download: [https://github.com/VirusTotal/yara](https://github.com/VirusTotal/yara)

---

## Project Structure
cyber/
│── rules/
│ └── malware_rules.yar
│── samples/
│ ├── file1.pdf
│ ├── file2.txt
│ ├── file3.exe
│ └── file4.txt
└── yara-master-v4.5.4-win64/
└── yara64.exe
└── run_yara_project.ps1

## How to Run

Open PowerShell and navigate to the project folder.

Run the script to automatically create rules, sample files, and scan:

.\run_yara_project.ps1


The script will:

Create the rules and samples folders

Generate sample files and YARA rules

Run YARA scan and show output

Save scan results to scan_output.txt for screenshots

---
