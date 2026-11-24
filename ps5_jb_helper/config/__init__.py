"""Configuration module for PS5 Jailbreak Helper."""
import json
from pathlib import Path
from typing import Any, Dict, Optional
import jsonschema
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "app": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "version": {"type": "string"},
                "author": {"type": "string"},
                "license": {"type": "string"}
            },
            "required": ["name", "version"]
        },
        "upstream": {
            "type": "object",
            "properties": {
                "host_repo": {"type": "string"},
                "host_ref": {"type": "string"},
                "overlay_repo": {"type": "string"},
                "overlay_branch": {"type": "string"},
                "ftpsrv_url": {"type": "string", "format": "uri"},
                "ftpsrv_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}
            },
            "required": ["host_repo", "host_ref", "overlay_repo", "overlay_branch", "ftpsrv_url", "ftpsrv_sha256"]
        },
        "network": {
            "type": "object",
            "properties": {
                "dns_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "http_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "https_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "static_ip": {"type": "string", "format": "ipv4"},
                "static_mask": {"type": "string", "format": "ipv4"},
                "ps5_ip": {"type": "string", "format": "ipv4"},
                "upstream_dns": {
                    "type": "array",
                    "items": {"type": "string", "format": "ipv4"},
                    "minItems": 1
                },
                "guide_domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1
                },
                "block_domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1
                },
                "dns_rate_limit": {"type": "integer", "minimum": 1, "default": 100},
                "http_rate_limit": {"type": "integer", "minimum": 1, "default": 50},
                "https_rate_limit": {"type": "integer", "minimum": 1, "default": 50}
            },
            "required": ["dns_port", "http_port", "https_port", "static_ip", "static_mask", "ps5_ip", "upstream_dns", "guide_domains", "block_domains"]
        },
        "payloads": {
            "type": "object",
            "properties": {
                "required": {"type": "array", "items": {"type": "string"}},
                "optional": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["required", "optional"]
        },
        "firmware": {
            "type": "object",
            "properties": {
                "min_version": {"type": "string"},
                "max_version": {"type": "string"},
                "supported": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["min_version", "max_version", "supported"]
        },
        "download": {
            "type": "object",
            "properties": {
                "timeout": {"type": "integer", "minimum": 1},
                "chunk_size": {"type": "integer", "minimum": 1024},
                "max_retries": {"type": "integer", "minimum": 0},
                "retry_delay": {"type": "number", "minimum": 0}
            },
            "required": ["timeout", "chunk_size", "max_retries", "retry_delay"]
        },
        "gui": {
            "type": "object",
            "properties": {
                "theme": {"type": "string", "enum": ["dark", "light", "system"]},
                "window_size": {"type": "string", "pattern": "^\\d+x\\d+$"},
                "min_window_size": {"type": "string", "pattern": "^\\d+x\\d+$"},
                "remember_window": {"type": "boolean", "default": True},
                "colors": {
                    "type": "object",
                    "properties": {
                        "bg": {"type": "string", "pattern": "^#[0-9a-fA-F]{6}$"},
                        "card": {"type": "string", "pattern": "^#[0-9a-fA-F]{6}$"},
                        "fg": {"type": "string", "pattern": "^#[0-9a-fA-F]{6}$"},
                        "accent": {"type": "string", "pattern": "^#[0-9a-fA-F]{6}$"},
                        "success": {"type": "string", "pattern": "^#[0-9a-fA-F]{6}$"},
                        "warning": {"type": "string", "pattern": "^#[0-9a-fA-F]{6}$"},
                        "error": {"type": "string", "pattern": "^#[0-9a-fA-F]{6}$"},
                        "muted": {"type": "string", "pattern": "^#[0-9a-fA-F]{6}$"}
                    },
                    "required": ["bg", "card", "fg", "accent", "success", "warning", "error", "muted"]
                }
            },
            "required": ["theme", "window_size", "min_window_size", "colors"]
        },
        "logging": {
            "type": "object",
            "properties": {
                "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
                "format": {"type": "string"},
                "max_lines": {"type": "integer", "minimum": 100}
            },
            "required": ["level", "format", "max_lines"]
        }
    },
    "required": ["app", "upstream", "network", "payloads", "firmware", "download", "gui", "logging"]
}


DEFAULT_CONFIG = {
    "app": {"name": "Sekt0r Auto Jailbreak Tool", "version": "1.2.0", "author": "Security Research", "license": "MIT"},
    "upstream": {
        "host_repo": "arg0WAK/WAK1360-Relapse",
        "host_ref": "b2398fd5bea116f990595e0a187ae94d8c6db43d",
        "overlay_repo": "ThatRetiredDude/ps5-relapse-selfhost",
        "overlay_branch": "main",
        "ftpsrv_url": "https://github.com/ps5-payload-dev/ftpsrv/releases/download/v0.21.1/ftpsrv-ps5.elf",
        "ftpsrv_sha256": "7d4b31c83eae4e056580482a3a074e1db25922efc74ac1e439473b45d71a5938"
    },
    "network": {
        "dns_port": 53,
        "http_port": 80,
        "https_port": 443,
        "static_ip": "192.168.100.1",
        "static_mask": "255.255.255.0",
        "ps5_ip": "192.168.100.2",
        "upstream_dns": ["1.1.1.1", "8.8.8.8"],
        "guide_domains": ["manuals.playstation.net", "manual.playstation.net", "doc.dl.playstation.net"],
        "block_domains": [
            "update.playstation.net", "update.playstation.com", "dservices.playstation.net",
            "fms.playstation.net", "pst-patch.playstation.net",
            "sonyentertainmentnetwork.com", "scea.com"
        ],
        "dns_rate_limit": 100,
        "http_rate_limit": 50,
        "https_rate_limit": 50
    },
    "payloads": {
        "required": ["OnionHEN.elf", "kstuff.elf", "shadowmountplus.elf", "ftpsrv-ps5.elf"],
        "optional": ["elfldr-ps5-1360.elf", "kexp_2026_05_25.bin", "nanodns.elf"]
    },
    "firmware": {
        "min_version": "7.00",
        "max_version": "13.60",
        "supported": [
            "7.00", "7.01", "7.02", "7.10", "7.11", "7.20", "7.30", "7.40", "7.50", "7.51", "7.55", "7.60", "7.61",
            "8.00", "8.01", "8.03", "8.10", "8.20", "8.21", "8.30", "8.40", "8.50", "8.51", "8.52", "8.60", "8.61",
            "9.00", "9.03", "9.04", "9.10", "9.20", "9.30", "9.40", "9.50", "9.51", "9.60",
            "10.00", "10.01", "10.02", "10.10", "10.20", "10.30", "10.40", "10.50", "10.51", "10.60", "10.61",
            "11.00", "11.10", "11.20", "11.30", "11.40", "11.50", "11.51", "11.60",
            "12.00", "12.02", "12.10", "12.20", "12.30", "12.40", "12.50", "12.60", "12.70",
            "13.00", "13.10", "13.20", "13.30", "13.40", "13.42", "13.50", "13.60"
        ]
    },
    "download": {
        "timeout": 60,
        "chunk_size": 65536,
        "max_retries": 3,
        "retry_delay": 2
    },
    "gui": {
        "theme": "dark",
        "window_size": "860x760",
        "min_window_size": "760x640",
        "remember_window": True,
        "colors": {
            "bg": "#101418", "card": "#1a2129", "fg": "#e5e7eb", "accent": "#3b82f6",
            "success": "#22c55e", "warning": "#fbbf24", "error": "#ef4444", "muted": "#9ca3af"
        }
    },
    "logging": {
        "level": "INFO",
        "format": "[%(asctime)s] %(levelname)s: %(message)s",
        "max_lines": 1000
    }
}


def deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dictionaries."""
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def validate_config(config: dict) -> tuple[bool, list[str]]:
    """Validate config against schema. Returns (is_valid, errors)."""
    try:
        jsonschema.validate(instance=config, schema=CONFIG_SCHEMA)
        return True, []
    except jsonschema.ValidationError as e:
        return False, [str(e)]
    except Exception as e:
        return False, [f"Validation error: {e}"]


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from file with validation and defaults."""
    config = DEFAULT_CONFIG.copy()

    if config_path.is_file():
        try:
            with config_path.open("r", encoding="utf-8") as f:
                user_config = json.load(f)
            config = deep_merge(config, user_config)
        except Exception as e:
            print(f"Warning: Failed to load config.json: {e}, using defaults")

    # Validate
    is_valid, errors = validate_config(config)
    if not is_valid:
        print(f"Warning: Config validation failed: {errors}")

    return config


def save_config(config: dict, config_path: Path) -> bool:
    """Save configuration to file."""
    try:
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False


def get_config_value(config: dict, key_path: str, default: Any = None) -> Any:
    """Get nested config value using dot notation (e.g., 'network.dns_port')."""
    keys = key_path.split(".")
    value = config
    for k in keys:
        if isinstance(value, dict) and k in value:
            value = value[k]
        else:
            return default
    return value


# Global config instance (loaded from default config file location)
from pathlib import Path
import sys

def _get_base() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent.parent


CONFIG_FILE = _get_base() / "config.json"
CFG = load_config(CONFIG_FILE)