# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Unit tests for the email domain restriction logic introduced in Adapter.sanitize_email().

The private helper __check_email_domain() is exercised indirectly through
sanitize_email() with a mocked get_configuration_value so these tests are
fully isolated from the database and instance configuration.
"""

import pytest
from unittest.mock import patch, MagicMock

from plane.authentication.adapter.error import (
    AuthenticationException,
    AUTHENTICATION_ERROR_CODES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_adapter(allowed_domains_value: str | None):
    """Return a minimal Adapter instance whose get_configuration_value is
    patched to return *allowed_domains_value* for ALLOWED_EMAIL_DOMAINS."""
    from plane.authentication.adapter.base import Adapter

    request = MagicMock()
    adapter = Adapter(request=request, provider="email")

    # Patch at the module level so the private method picks it up
    patcher = patch(
        "plane.authentication.adapter.base.get_configuration_value",
        return_value=(allowed_domains_value,),
    )
    return adapter, patcher


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCheckEmailDomain:
    """Unit tests for Adapter.sanitize_email() domain-restriction logic."""

    # -- No restriction configured -------------------------------------------

    def test_empty_allowed_domains_permits_any_email(self):
        """When ALLOWED_EMAIL_DOMAINS is empty, every valid email is accepted."""
        adapter, patcher = _make_adapter("")
        with patcher:
            result = adapter.sanitize_email("user@anything.com")
        assert result == "user@anything.com"

    def test_none_allowed_domains_permits_any_email(self):
        """When ALLOWED_EMAIL_DOMAINS is None, every valid email is accepted."""
        adapter, patcher = _make_adapter(None)
        with patcher:
            result = adapter.sanitize_email("user@anything.com")
        assert result == "user@anything.com"

    def test_whitespace_only_allowed_domains_permits_any_email(self):
        """A value of whitespace only is treated as 'no restriction'."""
        adapter, patcher = _make_adapter("   ")
        with patcher:
            result = adapter.sanitize_email("user@anything.com")
        assert result == "user@anything.com"

    # -- Single domain configured --------------------------------------------

    def test_matching_domain_is_allowed(self):
        """An email whose domain matches the configured allowlist passes."""
        adapter, patcher = _make_adapter("company.com")
        with patcher:
            result = adapter.sanitize_email("alice@company.com")
        assert result == "alice@company.com"

    def test_non_matching_domain_is_rejected(self):
        """An email whose domain is NOT in the allowlist raises an exception."""
        adapter, patcher = _make_adapter("company.com")
        with patcher:
            with pytest.raises(AuthenticationException) as exc_info:
                adapter.sanitize_email("alice@other.com")
        assert exc_info.value.error_code == AUTHENTICATION_ERROR_CODES["EMAIL_DOMAIN_NOT_ALLOWED"]
        assert exc_info.value.error_message == "EMAIL_DOMAIN_NOT_ALLOWED"

    # -- Multiple domains configured -----------------------------------------

    def test_first_of_multiple_domains_is_allowed(self):
        """An email matching the first of several comma-separated domains passes."""
        adapter, patcher = _make_adapter("company.com,subsidiary.org")
        with patcher:
            result = adapter.sanitize_email("bob@company.com")
        assert result == "bob@company.com"

    def test_second_of_multiple_domains_is_allowed(self):
        """An email matching the second of several comma-separated domains passes."""
        adapter, patcher = _make_adapter("company.com,subsidiary.org")
        with patcher:
            result = adapter.sanitize_email("carol@subsidiary.org")
        assert result == "carol@subsidiary.org"

    def test_domain_not_in_multiple_list_is_rejected(self):
        """An email that matches none of the configured domains is rejected."""
        adapter, patcher = _make_adapter("company.com,subsidiary.org")
        with patcher:
            with pytest.raises(AuthenticationException) as exc_info:
                adapter.sanitize_email("dave@external.net")
        assert exc_info.value.error_code == AUTHENTICATION_ERROR_CODES["EMAIL_DOMAIN_NOT_ALLOWED"]

    # -- Whitespace / formatting tolerance -----------------------------------

    def test_whitespace_padded_domain_entries_are_trimmed(self):
        """Spaces around domain names in the config value are ignored."""
        adapter, patcher = _make_adapter("  company.com  ,  subsidiary.org  ")
        with patcher:
            result = adapter.sanitize_email("eve@company.com")
        assert result == "eve@company.com"

    def test_trailing_comma_does_not_create_empty_entry(self):
        """A trailing comma in the config should not create a catch-all empty entry."""
        adapter, patcher = _make_adapter("company.com,")
        with patcher:
            with pytest.raises(AuthenticationException):
                adapter.sanitize_email("mallory@other.com")

    # -- Case insensitivity --------------------------------------------------

    def test_domain_comparison_is_case_insensitive(self):
        """Domain matching is case-insensitive on both config and email sides."""
        adapter, patcher = _make_adapter("Company.COM")
        with patcher:
            result = adapter.sanitize_email("Frank@COMPANY.com")
        assert result == "frank@company.com"

    # -- sanitize_email still rejects invalid emails -------------------------

    def test_invalid_email_raises_before_domain_check(self):
        """Malformed addresses raise INVALID_EMAIL regardless of domain config."""
        adapter, patcher = _make_adapter("company.com")
        with patcher:
            with pytest.raises(AuthenticationException) as exc_info:
                adapter.sanitize_email("not-an-email")
        assert exc_info.value.error_code == AUTHENTICATION_ERROR_CODES["INVALID_EMAIL"]

    def test_empty_email_raises_before_domain_check(self):
        """An empty email raises INVALID_EMAIL regardless of domain config."""
        adapter, patcher = _make_adapter("company.com")
        with patcher:
            with pytest.raises(AuthenticationException) as exc_info:
                adapter.sanitize_email("")
        assert exc_info.value.error_code == AUTHENTICATION_ERROR_CODES["INVALID_EMAIL"]

    # -- Payload content -----------------------------------------------------

    def test_rejected_email_included_in_exception_payload(self):
        """The rejected email address is surfaced in the exception payload."""
        adapter, patcher = _make_adapter("company.com")
        with patcher:
            with pytest.raises(AuthenticationException) as exc_info:
                adapter.sanitize_email("hacker@evil.io")
        assert exc_info.value.payload.get("email") == "hacker@evil.io"
