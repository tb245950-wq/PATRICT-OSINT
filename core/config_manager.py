import os
import yaml
from typing import Any, Dict, Optional

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

class ConfigManager:
    """
    Manager konfigurasi terpusat untuk PATRICT-OSINT.
    Membaca config.yaml dan berkas .env untuk meng-override variabel lingkungan.
    """
    
    DEFAULT_CONFIG = {
        "app": {
            "name": "PATRICT-OSINT Framework",
            "version": "2.2.0",
            "timeout": 10,
            "max_concurrency": 25,
            "rotate_user_agent": True,
            "output_dir": "./output"
        },
        "modules": {
            "phone_osint": True,
            "location_osint": True,
            "caller_id_osint": True,
            "whatsapp_osint": True,
            "social_osint": True,
            "dorking_osint": True,
            "email_osint": True,
            "network_osint": True,
            "web_history": True
        },
        "proxy": {
            "enabled": False,
            "http_proxy": "",
            "socks5_proxy": ""
        },
        "reporting": {
            "generate_json": True,
            "generate_csv": True,
            "generate_html": True,
            "generate_graph": True,
            "theme": "dark"
        },
        "api_keys": {
            "truecaller_auth_token": "",
            "serper": "",
            "serpapi": ""
        }
    }
    
    def __init__(self, config_path: str = "config/config.yaml", env_path: str = ".env"):
        self.config_path = config_path
        self.env_path = env_path
        
        # Load .env file
        if DOTENV_AVAILABLE and os.path.exists(self.env_path):
            load_dotenv(self.env_path, override=True)
            
        self.config: Dict[str, Any] = self._load_config()
        self._apply_env_overrides()
        
    def _load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        return self._deep_merge(self.DEFAULT_CONFIG.copy(), loaded)
            except Exception as e:
                print(f"[!] Warning: Gagal membaca {self.config_path} ({e}). Menggunakan konfigurasi default.")
        return self.DEFAULT_CONFIG.copy()
        
    def _apply_env_overrides(self):
        """Mengambil override dari Environment Variables / .env"""
        if "APP_TIMEOUT" in os.environ:
            try:
                self.config["app"]["timeout"] = int(os.environ["APP_TIMEOUT"])
            except ValueError:
                pass
        if "APP_MAX_CONCURRENCY" in os.environ:
            try:
                self.config["app"]["max_concurrency"] = int(os.environ["APP_MAX_CONCURRENCY"])
            except ValueError:
                pass
        if "APP_OUTPUT_DIR" in os.environ:
            self.config["app"]["output_dir"] = os.environ["APP_OUTPUT_DIR"]
            
        if "PROXY_ENABLED" in os.environ:
            self.config["proxy"]["enabled"] = os.environ["PROXY_ENABLED"].lower() in ("true", "1", "yes")
        if "HTTP_PROXY" in os.environ:
            self.config["proxy"]["http_proxy"] = os.environ["HTTP_PROXY"]
        if "SOCKS5_PROXY" in os.environ:
            self.config["proxy"]["socks5_proxy"] = os.environ["SOCKS5_PROXY"]
            
        api_keys = self.config.setdefault("api_keys", {})
        for key in ["TRUECALLER_AUTH_TOKEN", "SERPER_API_KEY", "SERPAPI_KEY", "NUMVERIFY_API_KEY", "ABSTRACTAPI_KEY", "VERIPHONE_API_KEY", "HAVEIBEENPWNED_API_KEY", "LEAKCHECK_API_KEY", "DEHASHED_API_KEY", "DEHASHED_USERNAME"]:
            if key in os.environ and os.environ[key]:
                clean_key = key.lower().replace("_api_key", "").replace("_key", "")
                api_keys[clean_key] = os.environ[key]

    def _deep_merge(self, base: dict, update: dict) -> dict:
        for key, val in update.items():
            if isinstance(val, dict) and key in base and isinstance(base[key], dict):
                base[key] = self._deep_merge(base[key], val)
            else:
                base[key] = val
        return base
        
    def get(self, key_path: str, default: Any = None) -> Any:
        keys = key_path.split(".")
        val = self.config
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val
        
    def is_module_enabled(self, module_id: str) -> bool:
        return self.get(f"modules.{module_id}", True)
