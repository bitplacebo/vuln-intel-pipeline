import datetime
import json
import os
from pathlib import Path

import nvdlib

def fetch_nvd(year_or_recent):
    try:
    # Fetch recent CVEs (e.g., published or modified in the last 7 days)
    # You can adjust the parameters like `pubStartDate`, `pubEndDate`, `resultsPerPage`, etc.
    # For fetching recent updates, consider using `lastModStartDate` and `lastModEndDate`
        if year_or_recent == "recent":
            now = datetime.datetime.now()
            end_date = now.strftime("%Y-%m-%d %H:%M")
            print(end_date)
            end_date_minus_7 = now - datetime.timedelta(days=7)
            start_date = end_date_minus_7.strftime("%Y-%m-%d 00:00")

            vulnerabilities = nvdlib.searchCVE(pubStartDate=start_date, pubEndDate=end_date)
        else:
            year = int(year_or_recent)
            vulnerabilities = nvdlib.searchCVE(pubStartDate=f"{year}-01-01 00:00",
                                               pubEndDate=f"{year}-12-31 23:59")
        return vulnerabilities #returns list of CVE objects
    
    except Exception as e:
        print(f"Error fetching NVD data: {e}")
        return []
    
def save_to_json(cves, filename):
    json_list = []
    for cve in cves:
        # Convert CVE object to dictionary recursively
        cve_dict = cve_to_dict(cve)
        json_list.append(cve_dict)

    target_dir = Path("./storage/raw")
    file_path = target_dir / filename
    try:
        os.makedirs(target_dir, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(json_list, f, ensure_ascii=False, indent=4, default=str)
        print(f"Data saved to {file_path}")
    except Exception as e:
        print(f"Error saving data to JSON: {e}")

def cve_to_dict(obj):
    """Recursively convert an object to a dictionary."""
    if hasattr(obj, '__dict__'):
        result = {}
        for key, value in obj.__dict__.items():
            if isinstance(value, list):
                result[key] = [cve_to_dict(item) for item in value]
            elif hasattr(value, '__dict__'):
                result[key] = cve_to_dict(value)
            else:
                result[key] = value
        return result
    else:
        return obj
    
def main():
    """main loop to fetch NVD data and save to JSON"""

    print("Fetching NVD data...")
    year_or_recent = "recent"  # Change to a specific year like "2023" to fetch that year's CVEs
    vulnerabilities = fetch_nvd(year_or_recent)
    #vulnerabilities = "[{'id': 'CVE-2025-41730', 'sourceIdentifier': 'info@cert.vde.com', 'published': '2025-...': 5.9, 'score': ['V31', 9.8, 'CRITICAL']}, {'id': 'CVE-2025-41732', 'sourceIdentifier': 'info@cert.vde.com', 'published': '2025-...': 5.9, 'score': ['V31', 9.8, 'CRITICAL']}, {'id': 'CVE-2025-13953', 'sourceIdentifier': 'cve-coordination@incibe.es', 'published...TICAL', 'score': ['V40', 9.3, 'CRITICAL']}, {'id': 'CVE-2025-41358', 'sourceIdentifier': 'cve-coordination@incibe.es', 'published...y': 'HIGH', 'score': ['V40', 8.3, 'HIGH']}, {'id': 'CVE-2024-2104', 'sourceIdentifier': 'info@cert.vde.com', 'published': '2025-1...core': 5.9, 'score': ['V31', 8.8, 'HIGH']}, {'id': 'CVE-2024-2105', 'sourceIdentifier': 'info@cert.vde.com', 'published': '2025-1...re': 3.6, 'score': ['V31', 6.5, 'MEDIUM']}, {'id': 'CVE-2025-13184', 'sourceIdentifier': 'cret@cert.org', 'published': '2025-12-1...': 5.9, 'score': ['V31', 9.8, 'CRITICAL']}]"
    
    print("Saving NVD data to JSON...")
    save_to_json(vulnerabilities, f"nvd_{year_or_recent}.json")

if __name__ == "__main__":
    main()     # Fetch CVEs for a specific years or recent updates