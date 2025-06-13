import csv
import tldextract


def extract_keyword(csv_path: str) -> str:
    keywords = set()
    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get('domain', '').strip()
            if not domain:
                continue
            ext = tldextract.extract(domain)
            if ext.domain:
                keywords.add(ext.domain)
    
    result = sorted(list(keywords))
    return result[0] if result else "" 

