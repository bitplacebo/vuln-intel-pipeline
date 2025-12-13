import json
from pathlib import Path

def parse_nvd_json(file_path):
    """
    Parse NVD JSON file and extract canonical CVE fields.

    Args:
        file_path (str): Path to the NVD JSON file

    Returns:
        list: List of dictionaries with extracted CVE fields
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        cves = json.load(f)

    parsed_cves = []

    for cve in cves:
        # Extract basic fields
        cve_id = cve.get('id')
        published = cve.get('published')
        last_modified = cve.get('lastModified')
        risk_score = None #use highest version score available
        base_score = None

        # Extract description (English)
        description = ""
        descriptions = cve.get('descriptions', [])

        # Skip rejected CVEs
        words = descriptions[0].get('value').split(maxsplit=1)
        if words[0] == "Rejected":
            continue #break out of loop ignore rejected CVEs

        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value')
                break

        # Extract CVSS scores
        cvss_v2 = None
        cvss_v31 = None
        cvss_v4 = None

        metrics = cve.get('metrics', {})

        # CVSS v2
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
            cvss_v2 = {
                'version': cvss_data.get('version'),
                'vectorString': cvss_data.get('vectorString'),
                'baseScore': cvss_data.get('baseScore'),
                'baseSeverity': cvss_data.get('baseSeverity')
            }
            base_score = cvss_data.get('baseScore')

        # CVSS v3.1
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            cvss_v31 = {
                'version': cvss_data.get('version'),
                'vectorString': cvss_data.get('vectorString'),
                'baseScore': cvss_data.get('baseScore'),
                'baseSeverity': cvss_data.get('baseSeverity')
            }
            base_score = cvss_data.get('baseScore')

        # CVSS v4
        if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
            cvss_data = metrics['cvssMetricV40'][0].get('cvssData', {})
            cvss_v4 = {
                'version': cvss_data.get('version'),
                'vectorString': cvss_data.get('vectorString'),
                'baseScore': cvss_data.get('baseScore'),
                'baseSeverity': cvss_data.get('baseSeverity')
            }
            base_score = cvss_data.get('baseScore')

        # Determine risk score (highest available)
        if base_score is not None:
            risk_score = int(base_score * 10)


        # Extract CWE list
        cwe_list = []
        weaknesses = cve.get('weaknesses', [])
        for weakness in weaknesses:
            descriptions = weakness.get('description', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    cwe_list.append(desc.get('value'))

        # Create parsed CVE dict
        parsed_cve = {
            'id': cve_id,
            'description': description,
            'published': published,
            'lastModified': last_modified,
            'cvss_v2': cvss_v2,
            'cvss_v31': cvss_v31,
            'cvss_v4': cvss_v4,
            'risk_score': risk_score,
            'cwe_list': cwe_list,
        }

        parsed_cves.append(parsed_cve)

    return parsed_cves

if __name__ == "__main__":
    # Example usage
    file_path = Path("./storage/raw/nvd_recent.json")
    parsed_data = parse_nvd_json(file_path)

    # Print first CVE as example
    if parsed_data:
        print(json.dumps(parsed_data[0], indent=2))

    # Optionally save to new JSON
    output_path = Path("./storage/parsed/nvd_recent_parsed.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(parsed_data, f, indent=2, ensure_ascii=False)
    print(f"Parsed data saved to {output_path}")