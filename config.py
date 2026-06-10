import os
import yaml
from dotenv import load_dotenv

logging.basicConfig(filename="app.log", level=logging.INFO)

# Load environment variables from .env file
load_dotenv()

# Read API keys and other sensitive information
VT_API_KEY = os.getenv("VT_API_KEY")


# Load configuration from YAML
def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)


settings = load_config()
