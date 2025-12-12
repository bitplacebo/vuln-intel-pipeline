# run_ingest.py
from ingest import nvd_fetch

def main():
    print("Starting CVE ingest...")
    cve_count = nvd_fetch()
    print(f"Ingestion complete. Fetched {cve_count} CVEs.")

if __name__ == "__main__":
    main()
