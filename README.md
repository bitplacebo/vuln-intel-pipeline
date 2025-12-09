# vuln-intel-pipeline
Project: Vulnerability Intelligence Pipeline 

CVE Validation – Ensures the ID is real and properly formatted

Data Enrichment

Fetches NVD metadata

Pulls and attaches EPSS probability score

Checks KEV to determine if exploitation is confirmed

LLM Risk Summary – Generates a concise, engineering-ready explanation

Risk Categorization Rule

Critical → KEV-listed or EPSS ≥ 0.5

High → EPSS ≥ 0.2

Medium/Low otherwise

Containerized Deployment – Runs locally via Docker

Modular Architecture – Designed for learning and further extension

vuln-intel-pipeline/

├─ lambdas/                 # optional if using Lambda later

├─ ingest/                  # ingestion scripts

│  └─ nvd_fetch.py

├─ normalize/               # normalization and risk scoring

│  └─ normalize_cve.py

├─ storage/                 # DB schema + storage helpers

│  └─ db.py

├─ api/                     # FastAPI service

│  └─ main.py

├─ tests/                   # unit tests

├─ .github/workflows/       # CI (lint/tests/deploy)

├─ docs/

│  └─ architecture.md

├─ README.md

