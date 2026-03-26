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
# Module-level fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter():
    """Return a minimal Adapter instance with a mock request."""
    from plane.authentication.adapter.base import Adapter

    return Adapter(request=MagicMock(), provider="email")


@pytest.fixture
def patch_allowed_domains():
    """Return a callable that produces a context manager patching ALLOWED_EMAIL_DOMAINS.

    Usage::

        def test_something(adapter, patch_allowed_domains):
            with patch_allowed_domains("company.com"):
                result = adapter.sanitize_email("user@company.com")
            assert result == "user@company.com"
    """

    def _patch(value):
        return patch(
            "plane.authentication.adapter.base.get_configuration_value",
            return_value=(value,),
        )

    return _patch


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCheckEmailDomain:
    """Unit tests for Adapter.sanitize_email() domain-restriction logic."""

    # -- No restriction configured -------------------------------------------

    @pytest.mark.parametrize(
        "config_value",
        [
            pytest.param("", id="empty-string"),
            pytest.param(None, id="none"),
            pytest.param("   ", id="whitespace-only"),
        ],
    )
    def test_no_restriction_permits_any_email(self, adapter, patch_allowed_domains, config_value):
        """An unconfigured or empty allowlist accepts every valid email."""
        with patch_allowed_domains(config_value):
            assert adapter.sanitize_email("user@anything.com") == "user@anything.com"

    # -- Domain matching -------------------------------------------------------

    @pytest.mark.parametrize(
        "config,email,expected",
        [
            pytest.param("company.com", "alice@company.com", "alice@company.com", id="single-domain"),
            pytest.param(
                "company.com,subsidiary.org", "bob@company.com", "bob@company.com", id="multi-first"
            ),
            pytest.param(
                "company.com,subsidiary.org",
                "carol@subsidiary.org",
                "carol@subsidiary.org",
                id="multi-second",
            ),
            pytest.param(
                "  company.com  ,  subsidiary.org  ",
                "eve@company.com",
                "eve@company.com",
                id="whitespace-trimmed",
            ),
            pytest.param("Company.COM", "Frank@COMPANY.com", "frank@company.com", id="case-insensitive"),
        ],
    )
    def test_allowed_domain_passes(self, adapter, patch_allowed_domains, config, email, expected):
        """Emails from domains in the allowlist are accepted and normalised."""
        with patch_allowed_domains(config):
            assert adapter.sanitize_email(email) == expected

    # -- Domain blocking -------------------------------------------------------

    @pytest.mark.parametrize(
        "config,email",
        [
            pytest.param("company.com", "alice@other.com", id="single-domain-blocked"),
            pytest.param("company.com,subsidiary.org", "dave@external.net", id="multi-domain-absent"),
            pytest.param("company.com,", "mallory@other.com", id="trailing-comma-no-catch-all"),
        ],
    )
    def test_blocked_domain_raises(self, adapter, patch_allowed_domains, config, email):
        """Emails from domains absent from the allowlist raise EMAIL_DOMAIN_NOT_ALLOWED."""
        with patch_allowed_domains(config):
            with pytest.raises(AuthenticationException) as exc_info:
                adapter.sanitize_email(email)
        assert exc_info.value.error_code == AUTHENTICATION_ERROR_CODES["EMAIL_DOMAIN_NOT_ALLOWED"]
        assert exc_info.value.error_message == "EMAIL_DOMAIN_NOT_ALLOWED"

    def test_rejected_email_included_in_exception_payload(self, adapter, patch_allowed_domains):
        """The rejected email address is surfaced in the exception payload."""
        with patch_allowed_domains("company.com"):
            with pytest.raises(AuthenticationException) as exc_info:
                adapter.sanitize_email("hacker@evil.io")
        assert exc_info.value.payload.get("email") == "hacker@evil.io"

    # -- Invalid email handled before domain check ----------------------------

    @pytest.mark.parametrize(
        "email",
        [
            pytest.param("", id="empty"),
            pytest.param("not-an-email", id="malformed"),
        ],
    )
    def test_invalid_email_raises_before_domain_check(self, adapter, patch_allowed_domains, email):
        """Malformed or empty addresses raise INVALID_EMAIL before domain checking."""
        with patch_allowed_domains("company.com"):
            with pytest.raises(AuthenticationException) as exc_info:
                adapter.sanitize_email(email)
        assert exc_info.value.error_code == AUTHENTICATION_ERROR_CODES["INVALID_EMAIL"]
