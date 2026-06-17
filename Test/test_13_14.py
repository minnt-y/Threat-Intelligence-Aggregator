from ioc_extractor import extract_iocs_flat
from ioc_validator import filter_valid_domains

text = "Malicious domains: evil.com, fake-domain-12345.xyz, google.com"

# Step 1: Extract
iocs = extract_iocs_flat(text)
domains = [ioc["value"] for ioc in iocs if ioc["type"] == "domain"]

# Step 2: Validate
valid_domains = filter_valid_domains(domains)
print(f"Valid domains to analyze: {valid_domains}")
