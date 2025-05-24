import re
from collections import defaultdict
from typing import List, Dict

def extract_subdomain(url: str) -> str:
    """
    Remove protocol from the URL and return the subdomain.
    """
    return re.sub(r"^https?://", "", url).strip("/")

def extract_resource(cname_line: str) -> str:
    """
    Extract the core resource from a CNAME line.
    """
    cname_value = cname_line.replace("CNAME\t", "").strip(".")
    return cname_value

def build_resource_subdomain_map(nuclei_results: List[Dict]) -> List[Dict]:
    """
    Build a mapping of resource -> linked subdomains from a list of nuclei results.
    """
    resource_map = defaultdict(set)

    for item in nuclei_results:
        result = item.get("nulcei_result", {})
        target = result.get("target", "")
        url_list = result.get("url_list", [])

        subdomain = extract_subdomain(target)
        for cname in url_list:
            resource = extract_resource(cname)
            resource_map[resource].add(subdomain)

    structured_results = []
    for resource, subdomains in resource_map.items():
        resource_type = identify_resource_type(resource)
        structured_results.append({
            "resource": resource,
            "resource_type": resource_type,
            "linked_subdomains": sorted(list(subdomains))
        })

    return structured_results

def identify_resource_type(resource: str) -> str:
    """
    Identify the type of cloud resource based on patterns.
    """
    #if re.search(r"^s3[.-][a-z0-9-]+\.amazonaws\.com$", resource) or "s3-website" in resource:
    if "s3-website" in resource:
        return "AWS S3"
    elif "cloudfront.net" in resource:
        return "AWS CloudFront"
    # elif "herokuapp.com" in resource:
    #     return "Heroku"
    elif "github.io" in resource:
        return "GitHub Pages"
    # elif "netlify.app" in resource:
    #    return "Netlify"
    #elif "vercel.app" in resource:
    #    return "Vercel"
    else:
        return "Unknown"
