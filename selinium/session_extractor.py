"""
session_extractor.py
Extracts session data (cookies, JWT, tokens) from the browser after authentication.
"""

import json
import logging
from typing import Optional
from selenium import webdriver

logger = logging.getLogger(__name__)


class SessionExtractor:
    """
    Extracts all forms of session/auth tokens from the browser post-login.
    Handles: Cookies, localStorage JWT, sessionStorage JWT, Bearer tokens.
    """

    # Common key names used to store auth tokens
    JWT_KEYS = [
        "token", "authToken", "auth_token", "accessToken", "access_token",
        "jwtToken", "jwt", "id_token", "idToken", "bearerToken", "bearer_token",
        "userToken", "sessionToken", "session_token", "Authorization",
        "auth", "user_token", "refresh_token", "refreshToken"
    ]

    def __init__(self, driver: webdriver.Remote):
        self.driver = driver

    def get_cookies(self) -> list:
        """Get all browser cookies."""
        return self.driver.get_cookies()

    def get_auth_cookies(self) -> list:
        """Filter cookies likely to be auth-related."""
        auth_keywords = [
            "session", "auth", "token", "jwt", "login", "user",
            "sid", "csrftoken", "csrf", "sso", "oauth", "access"
        ]
        all_cookies = self.get_cookies()
        auth_cookies = [
            c for c in all_cookies
            if any(kw in c["name"].lower() for kw in auth_keywords)
        ]
        return auth_cookies if auth_cookies else all_cookies  # Return all if none matched

    def get_local_storage(self) -> dict:
        """Dump entire localStorage."""
        try:
            result = self.driver.execute_script("""
                let store = {};
                for (let i = 0; i < localStorage.length; i++) {
                    let key = localStorage.key(i);
                    store[key] = localStorage.getItem(key);
                }
                return store;
            """)
            return result or {}
        except Exception as e:
            logger.warning(f"Could not access localStorage: {e}")
            return {}

    def get_session_storage(self) -> dict:
        """Dump entire sessionStorage."""
        try:
            result = self.driver.execute_script("""
                let store = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    let key = sessionStorage.key(i);
                    store[key] = sessionStorage.getItem(key);
                }
                return store;
            """)
            return result or {}
        except Exception as e:
            logger.warning(f"Could not access sessionStorage: {e}")
            return {}

    def find_jwt_in_storage(self) -> Optional[dict]:
        """Search localStorage and sessionStorage for JWT tokens."""
        found = {}

        for storage_name, storage in [
            ("localStorage", self.get_local_storage()),
            ("sessionStorage", self.get_session_storage())
        ]:
            for key, value in storage.items():
                if not value:
                    continue
                # Direct key match
                if any(jwt_key.lower() == key.lower() for jwt_key in self.JWT_KEYS):
                    found[f"{storage_name}.{key}"] = value
                    continue
                # Try parsing JSON values that may contain tokens
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, dict):
                        for jwt_key in self.JWT_KEYS:
                            if jwt_key in parsed:
                                found[f"{storage_name}.{key}.{jwt_key}"] = parsed[jwt_key]
                except (json.JSONDecodeError, TypeError):
                    # Check if value itself looks like a JWT (3 base64 parts)
                    if isinstance(value, str) and value.count(".") == 2 and len(value) > 50:
                        found[f"{storage_name}.{key}"] = value

        return found if found else None

    def get_current_url(self) -> str:
        return self.driver.current_url

    def get_page_title(self) -> str:
        return self.driver.title

    def extract_all(self) -> dict:
        """
        Master extraction: pulls everything and returns a structured session report.
        """
        all_cookies = self.get_cookies()
        auth_cookies = self.get_auth_cookies()
        local_storage = self.get_local_storage()
        session_storage = self.get_session_storage()
        jwt_tokens = self.find_jwt_in_storage()

        # Build a clean "ready to inject" summary
        injection_ready = {}

        # Cookie header format
        if auth_cookies:
            injection_ready["cookie_header"] = "; ".join(
                f"{c['name']}={c['value']}" for c in auth_cookies
            )

        # Bearer token format
        if jwt_tokens:
            # Pick the most likely primary token
            primary_key = next(iter(jwt_tokens))
            primary_token = jwt_tokens[primary_key]
            if primary_token and not primary_token.startswith("{"):
                injection_ready["authorization_header"] = f"Bearer {primary_token}"
                injection_ready["raw_token"] = primary_token

        return {
            "current_url": self.get_current_url(),
            "page_title": self.get_page_title(),
            "all_cookies": all_cookies,
            "auth_cookies": auth_cookies,
            "local_storage": local_storage,
            "session_storage": session_storage,
            "jwt_tokens": jwt_tokens or {},
            "injection_ready": injection_ready,
            "summary": {
                "total_cookies": len(all_cookies),
                "auth_cookies_found": len(auth_cookies),
                "jwt_tokens_found": len(jwt_tokens) if jwt_tokens else 0,
                "local_storage_keys": len(local_storage),
                "session_storage_keys": len(session_storage),
            }
        }
