"""Limits on tool input and timeouts, shared by several modules.

Limits that belong to one module live there (e.g. compose.MAX_RECIPIENTS,
messages.MAX_EXTRACT_BYTES); these are used in more than one place.
"""

from __future__ import annotations

import httpx

# Tool input
MAX_FOLDER_NAME = 500
MAX_UIDS = 100  # per call
MAX_PART_ID = 50  # IMAP section number, e.g. "2.1"
MAX_MESSAGE_ID = 998  # RFC 5322 line length
MAX_FILENAME = 255
MAX_MIME_TYPE = 255
MAX_SEARCH_VALUE = 500
MAX_CONTACT_QUERY = 200
MAX_REFERENCES = 20  # Message-IDs kept in References / searched for in a thread

# Time
HOUR = 3600
DAY = 86400

# Network
IMAP_TIMEOUT_SECONDS = 30
SMTP_TIMEOUT_SECONDS = 60  # DATA of a large message over a slow link
HTTP_TIMEOUT = httpx.Timeout(20.0, connect=10.0)  # mailcow, CardDAV
BROKER_TIMEOUT = httpx.Timeout(30.0, connect=5.0)  # provisioning waits for mailcow
