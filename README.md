
# Linux-Based Automated Web & Network VAPT Dashboard Using Python

## Project Overview

This project is a Python-based Vulnerability Assessment and Penetration Testing (VAPT) dashboard designed to perform basic web security checks, network scanning, Linux configuration auditing, risk classification, and report generation.

## Features

- Network scanning using Nmap
- Web security header checks
- Linux configuration auditing
- Risk severity classification
- SQLite database storage
- Flask-based dashboard
- HTML report generation

## Technology Stack

- Python
- Flask
- SQLite
- Nmap
- Requests
- HTML and CSS
- Kali Linux

## Project Structure

- `app.py` — Flask dashboard
- `scanners/` — Network, web, and Linux scanning modules
- `analysis/` — Risk analysis and findings
- `database/` — SQLite database operations
- `reports/` — Report generation
- `templates/` — Dashboard and results HTML pages
- `static/` — CSS and JavaScript assets

## Installation

1. Install Python, Git, and Nmap.
2. Clone this repository.
3. Create and activate a Python virtual environment.
4. Install dependencies from `requirements.txt`.
5. Start the Flask application.

## Usage

Run the dashboard locally and scan only systems that you own or are explicitly authorized to assess.

OWASP Juice Shop can be used as a deliberately vulnerable practice target in an isolated lab.

## Disclaimer

This project is intended for educational and authorized security testing only.
