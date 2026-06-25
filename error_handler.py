import logging
import time
from typing import Callable, Optional

from logger_config import setup_logger

logger = setup_logger(__name__)


class APIError(Exception):
    """Base class for API-related errors."""

    pass


class RateLimitError(APIError):
    """Raised when API rate limit is exceeded."""

    pass


class TimeoutError(APIError):
    """Raised when request times out."""

    pass


class ValidationError(APIError):
    """Raised when response data is invalid."""

    pass


def safe_api_call(
    func: Callable, max_retries: int = 3, backoff: float = 2.0, *args, **kwargs
) -> Optional[dict]:
    """
    Execute API call with retry and exponential backoff.
    """
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"API call attempt {attempt}/{max_retries}")
            result = func(*args, **kwargs)
            return result

        except RateLimitError as e:
            wait = backoff * (2 ** (attempt - 1))
            logger.warning(f"Rate limit hit. Waiting {wait}s before retry...")
            time.sleep(wait)

        except TimeoutError as e:
            wait = backoff * attempt
            logger.warning(f"Timeout. Retrying in {wait}s...")
            time.sleep(wait)

        except ValidationError as e:
            logger.error(f"Data validation failed: {e}")
            return None

        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return None

    logger.error(f"All {max_retries} retries exhausted")
    return None


def parse_vt_response(response: dict) -> dict:
    """Safely parse VirusTotal API response."""
    try:
        data = response.get("data", {})
        if not data:
            raise ValidationError("Missing 'data' field in response")

        attributes = data.get("attributes", {})
        if not attributes:
            raise ValidationError("Missing 'attributes' field in data")

        stats = attributes.get("last_analysis_stats", {})
        if not stats:
            raise ValidationError("Missing 'last_analysis_stats' in attributes")

        return stats

    except (KeyError, TypeError) as e:
        raise ValidationError(f"Invalid response structure: {e}")


# Test
if __name__ == "__main__":
    # 1. Normal function
    def success_func():
        return {"status": "OK"}

    result = safe_api_call(success_func)
    print(f"Success test: {result}")

    # 2. Function that fails then succeeds
    call_count = 0

    def flaky_func():
        global call_count
        call_count += 1
        if call_count < 3:
            raise TimeoutError("Simulated timeout")
        return {"status": "recovered"}

    result = safe_api_call(flaky_func, max_retries=3)
    print(f"Retry test: {result} (took {call_count} attempts)")

    # 3. Always fails
    def fail_func():
        raise RateLimitError("Always blocked")

    result = safe_api_call(fail_func, max_retries=2, backoff=1)
    print(f"Fail test: {result}")
