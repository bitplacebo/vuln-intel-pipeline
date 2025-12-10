import json
import nvdlib

def fetch_nvd(year_or_recent):
    try:
    # Fetch recent CVEs (e.g., published or modified in the last 7 days)
    # You can adjust the parameters like `pubStartDate`, `pubEndDate`, `resultsPerPage`, etc.
    # For fetching recent updates, consider using `lastModStartDate` and `lastModEndDate`
        if year_or_recent == "recent":
            vulnerabilities = nvdlib.searchCVE(pubStartDate="now-7d")
        else:
            year = int(year_or_recent)
            vulnerabilities = nvdlib.searchCVE(pubStartDate=f"{year}-01-01T00:00:00:000 UTC-00:00",
                                               pubEndDate=f"{year}-12-31T23:59:59:999 UTC-00:00")
        
        
        return vulnerabilities
    

    
    except Exception as e:
        print(f"Error fetching NVD data: {e}")
        return []
