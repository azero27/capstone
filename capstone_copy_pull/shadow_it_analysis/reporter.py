def save_shadowit_mapping(mapping, scan_job_id):
    for entry in mapping:
        print(f"[TEST SAVE] Resource: {entry['resource']}")
        print(f"             Type: {entry['resource_type']}")
        print(f"             Linked Subdomains: {entry['linked_subdomains']}")
