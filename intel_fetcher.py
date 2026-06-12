import time
import requests
import logging
from ratelimit import limits, sleep_and_retry
from config import VT_API_KEY, settings

# Temporary logging configuration
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Read rate limit from config.yaml
RATE_LIMIT = settings["api"]["virustotal"]["rate_limit"]  # 4 request/minute
CALLS = 1
PERIOD = 60 / RATE_LIMIT


class VTClient:
    """
    VirusTotal API client for fetching threat intelligence.
    """

    def __init__(self):
        # Load configuration from config.yaml and .env
        self.api_key = VT_API_KEY
        self.base_url = settings["api"]["virustotal"]["base_url"]
        self.timeout = settings["api"]["virustotal"]["timeout"]
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}

    @sleep_and_retry
    @limits(calls=CALLS, period=PERIOD)
    def get_ip_report(self, ip_address):
        # Fetch threat intelligence report for a given IP address from VirusTotal API.
        url = f"{self.base_url}/ip_addresses/{ip_address}"

        try:
            logging.info(f"Quering IP: {ip_address}")
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            logging.info(
                f"Response status: {response.status_code} for IP: {ip_address}"
            )

            # check if the request was successful
            if response.status_code == 200:
                # Parse the JSON response and extract analysis stastics
                result = response.json()
                data = result.get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                return stats
            else:
                logging.error(f"Failed:{response.status_code}: {response.text}")
                return None

        except Exception as e:
            # Log any unexpected network or parsing errors
            logging.error(f"Unexpected error: {str(e)}")
            return None


if __name__ == "__main__":
    # Test the function with multiple calls
    client = VTClient()
    test_ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    for ip in test_ips:
        stats = client.get_ip_report(ip)
        if stats:
            print(f"Data retrieved successfully - {ip}: {stats}")
            # Extract and print the analysis stats from the response
        else:
            print("Failed to retrieve data. Check your app.log for details.")
