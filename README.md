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

                +-----------------------------+
                |  External Vulnerability Feeds|
                |-----------------------------|
                | - NVD API (CVE/CVSS)        |
                | - GitHub Security Advisories|
                | - Vendor Alerts (JSON/RSS)  |
                +--------------+--------------+
                               |
                               v
                 +-----------------------------+
                 |  Ingestion Layer (Python)   |
                 |-----------------------------|
                 | - Scheduled fetch jobs      |
                 | - Raw data collectors       |
                 | - Handles rate limiting     |
                 +--------------+--------------+
                               |
                               v
               +--------------------------------------+
               |   Normalization & Processing Layer   |
               |--------------------------------------|
               | - Parse CVE structure                |
               | - Normalize fields (CVSS, CWE, etc.) |
               | - Map exploitability indicators      |
               | - Apply Your Risk Score Model        |
               +-------------------+------------------+
                                   |
                                   v
                +-------------------------------------+
                |   Storage Layer (SQLite or DynamoDB) |
                |--------------------------------------|
                | - CVE table                          |
                | - Vendor advisories                  |
                | - Risk score results                 |
                +-------------------+------------------+
                                   |
                                   v
               +---------------------------------------+
               |    Analytics & Query API (FastAPI)    |
               |---------------------------------------|
               | - Query CVEs by risk score            |
               | - Search by CWE, CVSS severity        |
               | - Pull enriched risk intelligence     |
               +-------------------+--------------------+
                                   |
                                   v
         +-------------------------------------------------+
         |    Dashboard / Reports (optional extension)     |
         |-------------------------------------------------|
         | - Streamlit dashboard                           |
         | - “Top 10 Highest Risk CVEs Today”              |
         | - “Newly Published, High Risk”                  |
         +-------------------------------------------------+

                           GitHub Actions CI/CD
                         /-------------------------\
                        v                           v
              Linting / Unit Tests          Deploy API / Scheduler
