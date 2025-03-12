import json
import os
from typing import Dict, Any

class LanguageManager:
    def __init__(self):
        self.current_language = "en"
        self.translations: Dict[str, Dict[str, Any]] = {}
        self.load_translations()

    def load_translations(self):
        """Load all translation files from the translations directory."""
        translations_dir = os.path.join(os.path.dirname(__file__), "translations")
        if not os.path.exists(translations_dir):
            os.makedirs(translations_dir)

        for lang_file in os.listdir(translations_dir):
            if lang_file.endswith(".json"):
                lang_code = lang_file.split(".")[0]
                with open(os.path.join(translations_dir, lang_file), "r", encoding="utf-8") as f:
                    self.translations[lang_code] = json.load(f)

    def set_language(self, lang_code: str) -> bool:
        """Set the current language."""
        if lang_code in self.translations:
            self.current_language = lang_code
            return True
        return False

    def get_text(self, key: str, default: str = None) -> str:
        """Get translated text for a given key."""
        try:
            # Split the key by dots to access nested dictionary values
            keys = key.split(".")
            value = self.translations[self.current_language]
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default if default is not None else key

    def get_available_languages(self) -> Dict[str, str]:
        """Return available languages with their native names."""
        return {
            "en": "English",
            "tr": "Türkçe"
        }

    def get_current_language(self) -> str:
        """Return current language code."""
        return self.current_language 