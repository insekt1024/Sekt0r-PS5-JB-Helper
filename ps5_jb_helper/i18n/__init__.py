"""i18n module for PS5 Jailbreak Helper."""
import json
from pathlib import Path
from typing import Dict, Any


class I18n:
    """Internationalization manager with EN/FA support."""

    def __init__(self, base_path: Path, default_lang: str = "en"):
        self.base_path = base_path
        self.lang = default_lang
        self._strings: Dict[str, Any] = {}
        self._load(self.lang)

    def _load(self, lang: str) -> None:
        """Load strings for a language."""
        lang_file = self.base_path / f"{lang}.json"
        if lang_file.is_file():
            with lang_file.open("r", encoding="utf-8") as f:
                self._strings = json.load(f)
        else:
            # Fallback to English
            en_file = self.base_path / "en.json"
            if en_file.is_file():
                with en_file.open("r", encoding="utf-8") as f:
                    self._strings = json.load(f)
            else:
                self._strings = {}

    def set_lang(self, lang: str) -> None:
        """Change language and reload strings."""
        if lang != self.lang:
            self.lang = lang
            self._load(lang)

    def toggle_lang(self) -> str:
        """Toggle between EN and FA, return new language."""
        new_lang = "fa" if self.lang == "en" else "en"
        self.set_lang(new_lang)
        return new_lang

    def t(self, key: str, **kwargs: Any) -> str:
        """Translate a key with optional formatting."""
        s = self._strings.get(key, key)
        if kwargs:
            try:
                return s.format(**kwargs)
            except (KeyError, ValueError):
                return s
        return s

    def get_all(self) -> Dict[str, Any]:
        """Get all strings for current language."""
        return self._strings.copy()

    @property
    def is_rtl(self) -> bool:
        """Check if current language is RTL."""
        return self.lang == "fa"

    @property
    def opposite_lang(self) -> str:
        """Get the opposite language code."""
        return "fa" if self.lang == "en" else "en"


def create_i18n(base_path: Path, lang: str = "en") -> I18n:
    """Factory function to create I18n instance."""
    return I18n(base_path, lang)