diff_records_tools = [
    {
        "amass_result": [
        {
            "id": 100,
            "scan_result_id": 30,
            "prev_scan_result_id": 29,
            "target": "www.sskyroute.com",
            "diff_type": "removed",
            "description": "www.sskyroute.com 이(가) removed 처리됨 (amass)",
            # "tool": "amass"
        },
        {
            "id": 101,
            "scan_result_id": 31,
            "prev_scan_result_id": 30,
            "target": "sskyroute.com",
            "diff_type": "changed",
            "description": "sskyroute.com 이(가) changed 처리됨 (amass)",
            # "tool": "amass"
        }
        ]
    },
    {
        "nuclei_result": [
        {
            "id": 102,
            "scan_result_id": 32,
            "prev_scan_result_id": 31,
            "target": "sskyroute.com",
            "diff_type": "changed",
            "description": "sskyroute.com 이(가) changed 처리됨 (nuclei)",
            # "tool": "nuclei"
        },
        {
            "id": 103,
            "scan_result_id": 33,
            "prev_scan_result_id": 32,
            "target": "sskyroute.com",
            "diff_type": "added",
            "description": "sskyroute.com 이(가) added 처리됨 (nuclei)",
            # "tool": "nuclei"
        }
        ]
    },
    {
        "cloud_enum_result": [
        {
            "id": 104,
            "scan_result_id": 34,
            "prev_scan_result_id": 33,
            "target": "s31",
            "diff_type": "removed",
            "description": "www.sskyroute.com 이(가) removed 처리됨 (cloud_enum)",
            # "tool": "cloud_enum"
        },
        {
            "id": 105,
            "scan_result_id": 35,
            "prev_scan_result_id": 34,
            "target": "s32",
            "diff_type": "added",
            "description": "www.sskyroute.com 이(가) added 처리됨 (cloud_enum)",
            # "tool": "cloud_enum"
        }
        ]
    },
    {
        "s3scanner_result": [
        {
            "id": 106,
            "scan_result_id": 36,
            "prev_scan_result_id": 35,
            "target": "s31",
            "diff_type": "changed",
            "description": "sskyroute.com 이(가) changed 처리됨 (s3scanner)",
            # "tool": "s3scanner"
        },
        {
            "id": 107,
            "scan_result_id": 37,
            "prev_scan_result_id": 36,
            "target": "s32",
            "diff_type": "added",
            "description": "www.sskyroute.com 이(가) added 처리됨 (s3scanner)",
            # "tool": "s3scanner"
        }
        ]
    },
    {
        "nmap_result": [
        {
            "id": 108,
            "scan_result_id": 38,
            "prev_scan_result_id": 37,
            "target": "80",
            "diff_type": "added",
            "description": "sskyroute.com 이(가) added 처리됨 (nmap)",
            # "tool": "nmap"
        },
        {
            "id": 109,
            "scan_result_id": 39,
            "prev_scan_result_id": 38,
            "target": "22",
            "diff_type": "added",
            "description": "sskyroute.com 이(가) added 처리됨 (nmap)",
            # "tool": "nmap"
        }
        ]
    }
]

diff_records_shadow = [
    {
        "shadow_network_result": [
        {
            "id": 110,
            "scan_result_id": 40,
            "prev_scan_result_id": 39,
            "target": "91",
            "diff_type": "changed",
            "description": "sskyroute.com 이(가) changed 처리됨 (shadow_network)",
            # "tool": "shadow_network"
        },
        {
            "id": 111,
            "scan_result_id": 41,
            "prev_scan_result_id": 40,
            "target": "92",
            "diff_type": "changed",
            "description": "www.sskyroute.com 이(가) changed 처리됨 (shadow_network)",
            # "tool": "shadow_network"
        }
        ]
    },
    {
        "shadow_resource_result": [
        {
            "id": 112,
            "scan_result_id": 42,
            "prev_scan_result_id": 41,
            "target": "s3",
            "diff_type": "changed",
            "description": "sskyroute.com 이(가) changed 처리됨 (shadow_resource)",
            # "tool": "shadow_resource"
        },
        {
            "id": 113,
            "scan_result_id": 43,
            "prev_scan_result_id": 42,
            "target": "s31",
            "diff_type": "changed",
            "description": "www.sskyroute.com 이(가) changed 처리됨 (shadow_resource)",
            # "tool": "shadow_resource"
        }
        ]
    },
    {
        "shadow_domain_result": [
        {
            "id": 114,
            "scan_result_id": 44,
            "prev_scan_result_id": 43,
            "target": "sskyroute.com",
            "diff_type": "removed",
            "description": "sskyroute.com 이(가) removed 처리됨 (shadow_domain)",
            # "tool": "shadow_domain"
        },
        {
            "id": 115,
            "scan_result_id": 45,
            "prev_scan_result_id": 44,
            "target": "www.sskyroute.com",
            "diff_type": "removed",
            "description": "www.sskyroute.com 이(가) removed 처리됨 (shadow_domain)",
            # "tool": "shadow_domain"
        }
        ]
    }
]

def generate_mock_diff_records_tools():
    return diff_records_tools

def generate_mock_diff_records_shadow():
    return diff_records_shadow
