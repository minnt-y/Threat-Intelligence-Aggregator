import time
import requests
from ratelimit import limits, sleep_and_retry
from config import VT_API_KEY, settings
from error_handler import safe_api_call, RateLimitError, TimeoutError, ValidationError
from logger_config import setup_logger

logger = setup_logger(__name__)

# Read rate limit from config.yaml
VT_CONFIG = settings["api"]["virustotal"]
RATE_LIMIT = VT_CONFIG["rate_limit"]  # 4

CALLS = 1
PERIOD = 60 / RATE_LIMIT


class VTClient:
    """
    VirusTotal API client for fetching threat intelligence.
    """

    def __init__(self):
        self.api_key = VT_API_KEY
        self.base_url = VT_CONFIG["base_url"]
        self.timeout = VT_CONFIG["timeout"]
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}

    @sleep_and_retry
    @limits(calls=CALLS, period=PERIOD)
    def get_ip_report(self, ip_address: str) -> dict | None:
        """Fetch threat intelligence report for a given IP."""
        url = f"{self.base_url}/ip_addresses/{ip_address}"

        def _fetch():
            response = requests.get(url, headers=self.headers, timeout=self.timeout)

            if response.status_code == 429:
                raise RateLimitError("VT rate limit")
            elif response.status_code >= 500:
                raise TimeoutError("Server error")

            return response.json()

        try:
            logger.info(f"Quering IP: {ip_address}")
            result = safe_api_call(_fetch, max_retries=3)

            # check if the request was successful
            if result:
                data = result.get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                return stats
            else:
                logger.error(f"All retries failed for IP: {ip_address}")

        except Exception as e:
            # Log any unexpected network or parsing errors
            logger.error(f"Unexpected error: {str(e)}")
            return None


if __name__ == "__main__":
    # Test the function with multiple calls
    client = VTClient()
    test_ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    for ip in test_ips:
        stats = client.get_ip_report(ip)
        if stats:
            print(f"[OK] {ip}: {stats}")
            # Extract and print the analysis stats from the response
        else:
            print("[FAILed] - {ip}")
