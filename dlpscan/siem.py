"""SIEM integration adapters for shipping scan events to security platforms.

Provides adapters for Splunk HEC, Elasticsearch/OpenSearch, syslog,
generic webhooks, and Datadog.  All adapters implement the
:class:`SIEMAdapter` protocol and are thread-safe.

Usage::

    from dlpscan.siem import SplunkHECAdapter

    adapter = SplunkHECAdapter(
        url="https://splunk.example.com:8088",
        token="my-hec-token",
    )
    adapter.send({"action": "redact", "categories": ["credit_card"]})

    # Or create from environment variables:
    from dlpscan.siem import create_siem_from_env
    adapter = create_siem_from_env()  # reads DLPSCAN_SIEM_* vars
"""

import json
import logging
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from logging.handlers import SysLogHandler
from typing import Dict, Optional, runtime_checkable

try:
    from typing import Protocol
except ImportError:
    # Python 3.7 fallback
    from typing import Protocol  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Protocol
# ------------------------------------------------------------------

@runtime_checkable
class SIEMAdapter(Protocol):
    """Protocol that all SIEM adapters implement."""

    def send(self, event: dict) -> None:
        """Send a scan event to the SIEM platform.

        Args:
            event: Dictionary containing the scan event data.

        Raises:
            Exception: On transport or authentication failures.
        """
        ...


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _build_ssl_context(verify: bool = True) -> ssl.SSLContext:
    """Build an SSL context, optionally disabling certificate verification."""
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_post(
    url: str,
    data: bytes,
    headers: Dict[str, str],
    verify_ssl: bool = True,
    timeout: float = 30.0,
) -> int:
    """POST *data* to *url* and return the HTTP status code."""
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    ctx = _build_ssl_context(verify_ssl) if url.startswith("https") else None
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        logger.error("SIEM HTTP error %s: %s", exc.code, exc.reason)
        raise
    except urllib.error.URLError as exc:
        logger.error("SIEM connection error: %s", exc.reason)
        raise


def _enrich_event(event: dict) -> dict:
    """Add standard envelope fields if not already present."""
    enriched = dict(event)
    enriched.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    enriched.setdefault("host", socket.gethostname())
    enriched.setdefault("source", "dlpscan")
    return enriched


# ------------------------------------------------------------------
# Splunk HEC
# ------------------------------------------------------------------

class SplunkHECAdapter:
    """Send events to Splunk HTTP Event Collector.

    Args:
        url: Splunk HEC endpoint URL (e.g. ``https://splunk:8088``).
        token: HEC authentication token.
        source: Event source field (default ``dlpscan``).
        sourcetype: Event sourcetype (default ``_json``).
        verify_ssl: Whether to verify SSL certificates (default True).
    """

    def __init__(
        self,
        url: str,
        token: str,
        source: str = "dlpscan",
        sourcetype: str = "_json",
        verify_ssl: bool = True,
    ) -> None:
        self._url = url.rstrip("/") + "/services/collector/event"
        self._token = token
        self._source = source
        self._sourcetype = sourcetype
        self._verify_ssl = verify_ssl
        self._lock = threading.Lock()

    def send(self, event: dict) -> None:
        """Send an event to Splunk HEC."""
        payload = {
            "event": _enrich_event(event),
            "source": self._source,
            "sourcetype": self._sourcetype,
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Authorization": f"Splunk {self._token}",
            "Content-Type": "application/json",
        }
        with self._lock:
            _http_post(self._url, data, headers, verify_ssl=self._verify_ssl)

    def __repr__(self) -> str:
        return f"SplunkHECAdapter(url={self._url!r}, source={self._source!r})"


# ------------------------------------------------------------------
# Elasticsearch / OpenSearch
# ------------------------------------------------------------------

class ElasticsearchAdapter:
    """Send events to Elasticsearch or OpenSearch.

    Args:
        url: Cluster URL (e.g. ``https://es.example.com:9200``).
        index: Target index name (default ``dlpscan-events``).
        api_key: Optional API key for authentication (Base64-encoded).
        verify_ssl: Whether to verify SSL certificates (default True).
    """

    def __init__(
        self,
        url: str,
        index: str = "dlpscan-events",
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
    ) -> None:
        self._url = url.rstrip("/")
        self._index = index
        self._api_key = api_key
        self._verify_ssl = verify_ssl
        self._lock = threading.Lock()

    def send(self, event: dict) -> None:
        """Index an event into Elasticsearch."""
        endpoint = f"{self._url}/{self._index}/_doc"
        enriched = _enrich_event(event)
        data = json.dumps(enriched).encode("utf-8")
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"ApiKey {self._api_key}"
        with self._lock:
            _http_post(endpoint, data, headers, verify_ssl=self._verify_ssl)

    def __repr__(self) -> str:
        return f"ElasticsearchAdapter(url={self._url!r}, index={self._index!r})"


# ------------------------------------------------------------------
# Syslog (RFC 5424)
# ------------------------------------------------------------------

class SyslogAdapter:
    """Send events via syslog (RFC 5424).

    Uses :class:`logging.handlers.SysLogHandler` under the hood.

    Args:
        address: ``(host, port)`` tuple (default ``('localhost', 514)``).
        facility: Syslog facility name (default ``local0``).
        protocol: ``'udp'`` or ``'tcp'`` (default ``'udp'``).
    """

    _FACILITY_MAP = {
        "kern": SysLogHandler.LOG_KERN,
        "user": SysLogHandler.LOG_USER,
        "mail": SysLogHandler.LOG_MAIL,
        "daemon": SysLogHandler.LOG_DAEMON,
        "auth": SysLogHandler.LOG_AUTH,
        "syslog": SysLogHandler.LOG_SYSLOG,
        "lpr": SysLogHandler.LOG_LPR,
        "news": SysLogHandler.LOG_NEWS,
        "uucp": SysLogHandler.LOG_UUCP,
        "cron": SysLogHandler.LOG_CRON,
        "local0": SysLogHandler.LOG_LOCAL0,
        "local1": SysLogHandler.LOG_LOCAL1,
        "local2": SysLogHandler.LOG_LOCAL2,
        "local3": SysLogHandler.LOG_LOCAL3,
        "local4": SysLogHandler.LOG_LOCAL4,
        "local5": SysLogHandler.LOG_LOCAL5,
        "local6": SysLogHandler.LOG_LOCAL6,
        "local7": SysLogHandler.LOG_LOCAL7,
    }

    def __init__(
        self,
        address: tuple = ("localhost", 514),
        facility: str = "local0",
        protocol: str = "udp",
    ) -> None:
        facility_code = self._FACILITY_MAP.get(
            facility.lower(), SysLogHandler.LOG_LOCAL0
        )
        socktype = socket.SOCK_STREAM if protocol.lower() == "tcp" else socket.SOCK_DGRAM

        self._handler = SysLogHandler(
            address=address,
            facility=facility_code,
            socktype=socktype,
        )
        self._handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger = logging.getLogger("dlpscan.siem.syslog")
        # Avoid duplicate handlers on repeated instantiation.
        self._logger.handlers = [self._handler]
        self._logger.setLevel(logging.INFO)
        self._lock = threading.Lock()

    def send(self, event: dict) -> None:
        """Send an event as a JSON syslog message."""
        enriched = _enrich_event(event)
        message = json.dumps(enriched, default=str)
        with self._lock:
            self._logger.info(message)

    def __repr__(self) -> str:
        return f"SyslogAdapter(address={self._handler.address!r})"


# ------------------------------------------------------------------
# Generic Webhook
# ------------------------------------------------------------------

class WebhookAdapter:
    """Send events to a generic webhook URL (POST JSON).

    Args:
        url: The webhook endpoint URL.
        headers: Optional extra HTTP headers.
        verify_ssl: Whether to verify SSL certificates (default True).
    """

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = True,
    ) -> None:
        self._url = url
        self._extra_headers = headers or {}
        self._verify_ssl = verify_ssl
        self._lock = threading.Lock()

    def send(self, event: dict) -> None:
        """POST the event as JSON to the webhook URL."""
        enriched = _enrich_event(event)
        data = json.dumps(enriched).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(self._extra_headers)
        with self._lock:
            _http_post(self._url, data, headers, verify_ssl=self._verify_ssl)

    def __repr__(self) -> str:
        return f"WebhookAdapter(url={self._url!r})"


# ------------------------------------------------------------------
# Datadog Logs API
# ------------------------------------------------------------------

class DatadogAdapter:
    """Send events to the Datadog Logs API.

    Args:
        api_key: Datadog API key.
        site: Datadog site domain (default ``datadoghq.com``).
        source: Log source tag (default ``dlpscan``).
        service: Service name tag (default ``dlpscan``).
    """

    def __init__(
        self,
        api_key: str,
        site: str = "datadoghq.com",
        source: str = "dlpscan",
        service: str = "dlpscan",
    ) -> None:
        self._api_key = api_key
        self._url = f"https://http-intake.logs.{site}/api/v2/logs"
        self._source = source
        self._service = service
        self._lock = threading.Lock()

    def send(self, event: dict) -> None:
        """Send a log event to Datadog."""
        enriched = _enrich_event(event)
        payload = {
            "ddsource": self._source,
            "ddtags": f"service:{self._service}",
            "hostname": enriched.pop("host", socket.gethostname()),
            "message": enriched,
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "DD-API-KEY": self._api_key,
        }
        with self._lock:
            _http_post(self._url, data, headers)

    def __repr__(self) -> str:
        return f"DatadogAdapter(site={self._url!r}, source={self._source!r})"


# ------------------------------------------------------------------
# Factory from environment variables
# ------------------------------------------------------------------

def create_siem_from_env() -> Optional[SIEMAdapter]:
    """Create a SIEM adapter from ``DLPSCAN_SIEM_*`` environment variables.

    Supported env vars:
        DLPSCAN_SIEM_TYPE: One of ``splunk``, ``elasticsearch``, ``syslog``,
            ``webhook``, ``datadog``.

    Splunk:
        DLPSCAN_SIEM_URL: HEC endpoint URL.
        DLPSCAN_SIEM_TOKEN: HEC token.
        DLPSCAN_SIEM_SOURCE: Event source (optional, default ``dlpscan``).
        DLPSCAN_SIEM_SOURCETYPE: Sourcetype (optional, default ``_json``).
        DLPSCAN_SIEM_VERIFY_SSL: ``true``/``false`` (optional, default ``true``).

    Elasticsearch:
        DLPSCAN_SIEM_URL: Cluster URL.
        DLPSCAN_SIEM_INDEX: Index name (optional, default ``dlpscan-events``).
        DLPSCAN_SIEM_API_KEY: API key (optional).
        DLPSCAN_SIEM_VERIFY_SSL: ``true``/``false`` (optional).

    Syslog:
        DLPSCAN_SIEM_HOST: Syslog host (optional, default ``localhost``).
        DLPSCAN_SIEM_PORT: Syslog port (optional, default ``514``).
        DLPSCAN_SIEM_FACILITY: Facility name (optional, default ``local0``).
        DLPSCAN_SIEM_PROTOCOL: ``udp``/``tcp`` (optional, default ``udp``).

    Webhook:
        DLPSCAN_SIEM_URL: Webhook endpoint URL.
        DLPSCAN_SIEM_VERIFY_SSL: ``true``/``false`` (optional).

    Datadog:
        DLPSCAN_SIEM_API_KEY: Datadog API key.
        DLPSCAN_SIEM_SITE: Datadog site (optional, default ``datadoghq.com``).
        DLPSCAN_SIEM_SOURCE: Source tag (optional, default ``dlpscan``).
        DLPSCAN_SIEM_SERVICE: Service tag (optional, default ``dlpscan``).

    Returns:
        A configured :class:`SIEMAdapter` instance, or ``None`` if
        ``DLPSCAN_SIEM_TYPE`` is not set.
    """
    siem_type = os.environ.get("DLPSCAN_SIEM_TYPE", "").strip().lower()
    if not siem_type:
        return None

    verify_ssl_str = os.environ.get("DLPSCAN_SIEM_VERIFY_SSL", "true").strip().lower()
    verify_ssl = verify_ssl_str in ("true", "1", "yes", "on")

    if siem_type == "splunk":
        url = os.environ.get("DLPSCAN_SIEM_URL")
        token = os.environ.get("DLPSCAN_SIEM_TOKEN")
        if not url or not token:
            logger.error("Splunk SIEM requires DLPSCAN_SIEM_URL and DLPSCAN_SIEM_TOKEN")
            return None
        return SplunkHECAdapter(
            url=url,
            token=token,
            source=os.environ.get("DLPSCAN_SIEM_SOURCE", "dlpscan"),
            sourcetype=os.environ.get("DLPSCAN_SIEM_SOURCETYPE", "_json"),
            verify_ssl=verify_ssl,
        )

    if siem_type == "elasticsearch":
        url = os.environ.get("DLPSCAN_SIEM_URL")
        if not url:
            logger.error("Elasticsearch SIEM requires DLPSCAN_SIEM_URL")
            return None
        return ElasticsearchAdapter(
            url=url,
            index=os.environ.get("DLPSCAN_SIEM_INDEX", "dlpscan-events"),
            api_key=os.environ.get("DLPSCAN_SIEM_API_KEY"),
            verify_ssl=verify_ssl,
        )

    if siem_type == "syslog":
        host = os.environ.get("DLPSCAN_SIEM_HOST", "localhost")
        try:
            port = int(os.environ.get("DLPSCAN_SIEM_PORT", "514"))
        except ValueError:
            port = 514
        return SyslogAdapter(
            address=(host, port),
            facility=os.environ.get("DLPSCAN_SIEM_FACILITY", "local0"),
            protocol=os.environ.get("DLPSCAN_SIEM_PROTOCOL", "udp"),
        )

    if siem_type == "webhook":
        url = os.environ.get("DLPSCAN_SIEM_URL")
        if not url:
            logger.error("Webhook SIEM requires DLPSCAN_SIEM_URL")
            return None
        return WebhookAdapter(url=url, verify_ssl=verify_ssl)

    if siem_type == "datadog":
        api_key = os.environ.get("DLPSCAN_SIEM_API_KEY")
        if not api_key:
            logger.error("Datadog SIEM requires DLPSCAN_SIEM_API_KEY")
            return None
        return DatadogAdapter(
            api_key=api_key,
            site=os.environ.get("DLPSCAN_SIEM_SITE", "datadoghq.com"),
            source=os.environ.get("DLPSCAN_SIEM_SOURCE", "dlpscan"),
            service=os.environ.get("DLPSCAN_SIEM_SERVICE", "dlpscan"),
        )

    logger.error("Unknown SIEM type: %r", siem_type)
    return None
