# Multithreaded Web Reconnaissance & Vulnerability Scanner

## Overview

This project is a Python-based web reconnaissance and vulnerability enumeration tool designed to perform passive fingerprinting and basic security analysis against web-facing infrastructure.

The scanner identifies open web services, performs HTTP banner grabbing and header analysis, fingerprints technologies such as Apache, Nginx, IIS, and Cloudflare, and retrieves publicly disclosed CVEs from the NVD database using CPE-based matching.

The project demonstrates practical cybersecurity concepts including:
- Port scanning
- Service fingerprinting
- Passive reconnaissance
- TLS/SSL handling
- HTTP analysis
- Vulnerability enumeration
- Concurrent scanning using multithreading

---

# Features

## Port Scanning
- Scans configurable port ranges
- Supports common web ports:
  - 80
  - 443
  - 8080
  - 8000
  - 8443

## Banner Grabbing
- Sends HTTP/HTTPS requests
- Extracts HTTP response headers
- Identifies web technologies

## Technology Fingerprinting
Detects:
- Apache
- Nginx
- IIS
- Cloudflare

## Vulnerability Enumeration
- Maps identified technologies to CPEs
- Queries NVD API for CVEs
- Displays:
  - CVE IDs
  - CVSS scores
  - vulnerability descriptions

## Multithreading
- Uses worker threads for faster scanning
- Queue-based concurrent architecture

---

# Technologies Used

- Python
- socket
- ssl
- threading
- queue
- requests
- regular expressions

---

# Architecture

```text
Target Host
     ↓
Port Scan
     ↓
Banner Grabbing
     ↓
HTTP Header Analysis
     ↓
Technology Fingerprinting
     ↓
CPE Mapping
     ↓
NVD CVE Lookup
     ↓
Vulnerability Report
```

---

# Usage

Run the program:

```bash
python scanner.py
```

Example:

```txt
Enter target: scanme.nmap.org
Enter start port: 1
Enter end port: 1000
```

---

# Example Output

```txt
Checking port 80...

Possible web server found.

Server: nginx
Version: 1.18.0

Found 5 CVEs

ID: CVE-2021-23017
CVSS: 7.7
Description: Nginx resolver vulnerability...
```

---

# Limitations

This scanner performs passive fingerprinting and relies on publicly exposed HTTP metadata.

Modern websites frequently use:
- CDNs
- WAFs
- reverse proxies

such as Cloudflare, which may:
- hide backend technologies
- suppress version headers
- reduce fingerprinting accuracy

---

# Educational Purpose

This project was developed for educational and research purposes to better understand:
- Web reconnaissance
- Network programming
- Vulnerability intelligence
- Security scanning methodologies
- Modern defensive infrastructure
