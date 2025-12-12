"""
This module provides functions querying the NVD API. Args are either 
"recent" for the last 7 days or a specific year-month like "2023-06".

Functions:
    fetch_nvd: Returns a month or recent CVEs from the NVD API.
    save_to_json: Saves the fetched CVEs to a JSON file.
"""
import datetime
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
import nvdlib

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")


def fetch_nvd(p_range):
    """ Fetch recent CVEs (e.g., published or modified in the last 7 days)
        You can adjust the parameters like `pubStartDate`, `pubEndDate`, `resultsPerPage`, etc.
        For fetching recent updates, consider using `lastModStartDate` and `lastModEndDate`"""
    try:

        if p_range == "recent":
            now = datetime.datetime.now()
            end_date = now.strftime("%Y-%m-%d %H:%M")
            print(end_date)
            end_date_minus_7 = now - datetime.timedelta(days=7)
            start_date = end_date_minus_7.strftime("%Y-%m-%d 00:00")

            vulnerabilities = nvdlib.searchCVE(
                pubStartDate=start_date, pubEndDate=end_date, 
                key=NVD_API_KEY
            )
        else:
            year_month = p_range.split("-")
            year = int(year_month[0])
            month = int(year_month[1])

            end_date = datetime.datetime(year, month, 31, 23, 59).strftime(
                "%Y-%m-%d %H:%M"
            )
            start_date = datetime.datetime(year, month, 1, 0, 0).strftime(
                "%Y-%m-%d %H:%M"
            )
            vulnerabilities = nvdlib.searchCVE(
                pubStartDate=start_date, pubEndDate=end_date,
                key=NVD_API_KEY
            )
        return vulnerabilities  # returns list of CVE objects

    except Exception as e:
        print(f"Error fetching NVD data: {e}")
        return []


def save_to_json(cves, filename):
    """Save the fetched CVEs to a JSON file."""
    json_list = []
    for cve in cves:
        # Convert CVE object to dictionary recursively
        cve_dict = cve_to_dict(cve)
        json_list.append(cve_dict)

    target_dir = Path("./storage/raw")
    file_path = target_dir / filename
    try:
        os.makedirs(target_dir, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(json_list, f, ensure_ascii=False, indent=4, default=str)
        print(f"Data saved to {file_path}")
    except Exception as e:
        print(f"Error saving data to JSON: {e}")


def cve_to_dict(obj):
    """Recursively convert an object to a dictionary."""
    if hasattr(obj, "__dict__"):
        result = {}
        for key, value in obj.__dict__.items():
            if isinstance(value, list):
                result[key] = [cve_to_dict(item) for item in value]
            elif hasattr(value, "__dict__"):
                result[key] = cve_to_dict(value)
            else:
                result[key] = value
        return result
    return obj


def main(yearmonth_or_recent):
    """main loop to fetch NVD data and save to JSON"""
    # Args values of "recent" or to a specific year-month like "2023-06" to fetch that month's CVEs

    print(f"Fetching NVD data for {yearmonth_or_recent}...")

    vulnerabilities = fetch_nvd(yearmonth_or_recent)

    if not vulnerabilities:
        print("No vulnerabilities fetched.")
        return
    print("Saving NVD data to JSON...")
    save_to_json(vulnerabilities, f"nvd_{yearmonth_or_recent}.json")


if __name__ == "__main__":
    if len(sys.argv) < 1:
        print("No parameters provided. Using default 'recent' parameter.")
        ARG1 = "recent"
    else:
        ARG1 = sys.argv[1]

    main(ARG1)
