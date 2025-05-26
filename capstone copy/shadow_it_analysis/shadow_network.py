def compare_nmap_with_target_reference(nmap_results: list, target_mappings: dict):
    all_results = {}

    # Nmap 결과에서 타겟별로 그룹핑
    target_groups = {}
    for entry in nmap_results:
        target = entry.get("target")
        target_groups.setdefault(target, []).append(entry)

    for target, entries in target_groups.items():
        allowed = target_mappings.get(target, [])
        allowed_port_set = set(item['port'] for item in allowed)
        allowed_port_service_set = set((item['port'], item['service'].lower()) for item in allowed)

        unexpected_ports = []
        mismatched_services = []

        for entry in entries:
            port = entry.get("port_number")
            service = entry.get("service_name", "").lower()

            if port not in allowed_port_set:
                unexpected_ports.append({
                    "port": port,
                    "service": service,
                    "reason": "Not in allowed list"
                })
            elif (port, service) not in allowed_port_service_set:
                expected = next((item['service'] for item in allowed if item['port'] == port), "N/A")
                mismatched_services.append({
                    "port": port,
                    "expected_service": expected,
                    "actual_service": service,
                    "reason": "Service mismatch"
                })

        all_results[target] = {
            "unexpected_ports": unexpected_ports,
            "mismatched_services": mismatched_services
        }

    return all_results


nmap_results = [
    {"target": "15.165.170.99", "port_number": 22, "service_name": "ssh"},
    {"target": "15.165.170.99", "port_number": 80, "service_name": "apache httpd"},
    {"target": "192.168.0.10", "port_number": 3306, "service_name": "mysql"},
    {"target": "192.168.0.10", "port_number": 22, "service_name": "ssh"}
]

target_specific_mappings = {
    "15.165.170.99": [
        {"port": 22, "service": "ssh"},
        {"port": 443, "service": "https"}
    ],
    "192.168.0.10": [
        {"port": 3306, "service": "mysql"}
    ]
}

result = compare_nmap_with_target_reference(nmap_results, target_specific_mappings)

print("전체 비교 결과")

for target, findings in result.items():
    print(f"\n[Target]: {target}")

    print("허용되지 않은 포트")
    for item in findings["unexpected_ports"]:
        print(f"  - Port {item['port']} ({item['service']}): {item['reason']}")

    print("서비스 불일치")
    for item in findings["mismatched_services"]:
        print(f"  - Port {item['port']}: expected '{item['expected_service']}', got '{item['actual_service']}' → {item['reason']}")
