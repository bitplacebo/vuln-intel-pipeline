import datetime
import json
import nvdlib

def fetch_nvd(year_or_recent):
    try:
    # Fetch recent CVEs (e.g., published or modified in the last 7 days)
    # You can adjust the parameters like `pubStartDate`, `pubEndDate`, `resultsPerPage`, etc.
    # For fetching recent updates, consider using `lastModStartDate` and `lastModEndDate`
        if year_or_recent == "recent":
            now = datetime.datetime.now()
            end_date = now.strftime("%Y-%m-%d %H:%M")
            end_date_minus7 = now - datetime.timedelta(days=7)
            start_date = end_date_minus7.strftime("%Y-%m-%d %H:%M")

            vulnerabilities = nvdlib.searchCVE(pubStartDate=start_date, pubEndDate=end_date)
        else:
            year = int(year_or_recent)
            vulnerabilities = nvdlib.searchCVE(pubStartDate=f"{year}-01-01T00:00:00:000 UTC-00:00",
                                               pubEndDate=f"{year}-12-31T23:59:59:999 UTC-00:00")
        
        
        return vulnerabilities
    

    
    except Exception as e:
        print(f"Error fetching NVD data: {e}")
        return []

def main():
    year_or_recent = "recent"  # Change to a specific year like "2023" to fetch that year's CVEs
    vulnerabilities = fetch_nvd(year_or_recent)
    
    for vuln in vulnerabilities:
        print(vuln)

if __name__ == "__main__":
    main()     # Fetch CVEs for a specific years or recent updates