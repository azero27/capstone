import re
from collections import defaultdict
import json

def extract_resource_identifier(resource: str) -> str:
    parts = resource.split('.')
    return parts[0] if parts else ""

def identify_resource_type(resource: str) -> str:
    if "s3-website" in resource or "s3.amazonaws.com" in resource:
        return "AWS S3"
    elif "cloudfront.net" in resource:
        return "AWS CloudFront"
    elif "github.io" in resource:
        return "GitHub Pages"
    # elif "netlify.app" in resource:
    #    return "Netlify"
    #elif "vercel.app" in resource:
    #    return "Vercel"
    else:
        return "Unknown"

def analyze_nuclei_shadow_domains(parsed_results, user_resources):
    resource_map = defaultdict(set)
    exposure_results = []
    confirmed_dangling = []
    known_links = []

    for result in parsed_results:
        target = result.get("target", "")
        url_list = result.get("url_list", [])
        vuln_msg = result.get("vulnerability", "").lower()

        for entry in url_list:
            if not entry.startswith("CNAME\t"):
                continue

            resource = entry.replace("CNAME\t", "").strip(".").lower()
            resource_type = identify_resource_type(resource)
            resource_identifier = extract_resource_identifier(resource)
            resource_map[resource].add(target)

            base_entry = {
                "resource": resource,
                "resource_type": resource_type,
                "resource_identifier": resource_identifier,
                "linked_domains": sorted(resource_map[resource])
            }

            if resource_type == "AWS S3":
                base_entry["is_user_owned"] = resource_identifier in user_resources

            if "[dns] and [http] matched" in vuln_msg:
                base_entry["status"] = "dangling_dns"
                confirmed_dangling.append(base_entry)

            elif "[dns] matched" in vuln_msg and "[http]" not in vuln_msg:
                if resource_type == "AWS S3" and resource_identifier in user_resources:
                    base_entry["status"] = "linked_known_resource"
                    known_links.append(base_entry)
                else:
                    base_entry["status"] = "potential_exposure"
                    exposure_results.append(base_entry)

    result =  {
        "dangling_dns": confirmed_dangling,
        "potential_exposure": exposure_results,
        "linked_known_resource": known_links
    }

    print(json.dumps(result, indent=2))

    return result

parsed_nuclei_results = [
    {
        "target": "cdn.skyroute.com",
        "url_list": ["CNAME\tbucket1.s3.amazonaws.com"],
        "vulnerability": "detect-dangling-s3-cname [dns] matched"
    },
    {
        "target": "img.skyroute.com",
        "url_list": ["CNAME\tmy-owned-bucket.s3.amazonaws.com"],
        "vulnerability": "detect-dangling-s3-cname [dns] matched"
    },
    {
        "target": "static.skyroute.com",
        "url_list": ["CNAME\tstatic-site.github.io"],
        "vulnerability": "detect-dangling-s3-cname [dns] matched"
    },
    {
        "target": "media.skyroute.com",
        "url_list": ["CNAME\td111111abcdef8.cloudfront.net"],
        "vulnerability": "detect-dangling-s3-cname [dns] and [http] matched"
    }
]

user_resources = {"my-owned-bucket"} 


# results = analyze_nuclei_shadow_domains(parsed_nuclei_results, user_resources)

