import json
from pathlib import Path
from normalize.parse_nvd import parse_nvd_json

# Sample CVE data for testing
SAMPLE_CVE_DATA = [
    {
        "id": "CVE-2025-12345",
        "published": "2025-01-01T00:00:00.000",
        "lastModified": "2025-01-02T00:00:00.000",
        "descriptions": [
            {
                "lang": "en",
                "value": "Test vulnerability description"
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL"
                    }
                }
            ]
        },
        "weaknesses": [
            {
                "description": [
                    {
                        "lang": "en",
                        "value": "CWE-79"
                    }
                ]
            }
        ],
        "references": [
            {
                "url": "https://example.com/cve-2025-12345"
            }
        ]
    }
]

def test_parse_nvd_json_basic():
    """Test basic parsing of CVE data"""
    # Create a temporary JSON file
    test_file = Path("test_cve.json")
    with open(test_file, 'w', encoding='utf-8') as f:
        json.dump(SAMPLE_CVE_DATA, f)

    try:
        # Parse the data
        parsed_data = parse_nvd_json(test_file)

        # Assertions
        assert len(parsed_data) == 1
        cve = parsed_data[0]

        assert cve['id'] == "CVE-2025-12345"
        assert cve['description'] == "Test vulnerability description"
        assert cve['published'] == "2025-01-01T00:00:00.000"
        assert cve['lastModified'] == "2025-01-02T00:00:00.000"
        assert cve['cvss_v31']['baseScore'] == 9.8
        assert cve['cwe_list'] == ["CWE-79"]
     
    finally:
        # Clean up
        test_file.unlink()

def test_parse_nvd_json_rejected_cve():
    """Test that rejected CVEs are skipped"""
    rejected_cve_data = [
        {
            "id": "CVE-2025-99999",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Rejected reasons: something"
                }
            ]
        },
        SAMPLE_CVE_DATA[0]  # Include a valid CVE
    ]

    test_file = Path("test_rejected_cve.json")
    with open(test_file, 'w', encoding='utf-8') as f:
        json.dump(rejected_cve_data, f)

    try:
        parsed_data = parse_nvd_json(test_file)

        # Should only have the valid CVE
        assert len(parsed_data) == 1
        assert parsed_data[0]['id'] == "CVE-2025-12345"

    finally:
        test_file.unlink()

def test_parse_nvd_json_missing_fields():
    """Test parsing with missing optional fields"""
    minimal_cve_data = [
        {
            "id": "CVE-2025-67890",
            "published": "2025-01-01T00:00:00.000",
            "lastModified": "2025-01-02T00:00:00.000",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Minimal CVE"
                }
            ]
        }
    ]

    test_file = Path("test_minimal_cve.json")
    with open(test_file, 'w', encoding='utf-8') as f:
        json.dump(minimal_cve_data, f)

    try:
        parsed_data = parse_nvd_json(test_file)

        assert len(parsed_data) == 1
        cve = parsed_data[0]

        assert cve['cvss_v2'] is None
        assert cve['cvss_v31'] is None
        assert cve['cvss_v4'] is None
        assert cve['cwe_list'] == []

    finally:
        test_file.unlink()