import os
from pathlib import Path

APP_NAME = "Sigma Forge"
APP_VERSION = "1.0.0"

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
DATA_DIR = BASE_DIR / "data"
ATTACK_FILE = DATA_DIR / "attack" / "attack.json"
SAMPLES_DIR = BASE_DIR / "sample" / "rules"

HOST = os.getenv("SIGMA_FORGE_HOST", "127.0.0.1")
PORT = int(os.getenv("SIGMA_FORGE_PORT", "8000"))

MAX_RULES = int(os.getenv("SIGMA_FORGE_MAX_RULES", "5000"))
MAX_RULE_BYTES = int(os.getenv("SIGMA_FORGE_MAX_RULE_BYTES", "262144"))

WAZUH_RULE_ID_START = int(os.getenv("SIGMA_FORGE_WAZUH_ID_START", "100100"))
WAZUH_MAX_RULES_PER_SIGMA = int(os.getenv("SIGMA_FORGE_WAZUH_MAX_SPLIT", "64"))

MAX_LOG_BYTES = int(os.getenv("SIGMA_FORGE_MAX_LOG_BYTES", str(64 * 1024 * 1024)))
MAX_LOG_EVENTS = int(os.getenv("SIGMA_FORGE_MAX_LOG_EVENTS", "250000"))
LOG_QUERY_SECONDS = float(os.getenv("SIGMA_FORGE_LOG_QUERY_SECONDS", "10"))
SIGMAHQ_DIR = Path(os.getenv("SIGMA_FORGE_SIGMAHQ_DIR", str(DATA_DIR / "sigmahq")))
SIGMAHQ_URL = os.getenv("SIGMA_FORGE_SIGMAHQ_URL", "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip")
DEMO = os.getenv("SIGMA_FORGE_DEMO", "0").strip().lower() in ("1", "true", "yes")
