#!/usr/bin/env python3
"""
Local HTTP server for capturing SAML assertions from AWS IAM Identity Center.

Starts a lightweight server on localhost that acts as a SAML Assertion Consumer
Service (ACS) endpoint.  After the user authenticates via the AWS SSO portal,
the IdP POSTs the SAML response to this server, which extracts the assertion
and attributes for use with any SAML-federated Service Provider.

Usage:
    python saml_server.py --sso-url <AWS_SSO_URL>
"""

import argparse
import base64
import html
import http.server
import json
import logging
import os
import signal
import socketserver
import sys
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass, field
from typing import Optional

import xml.etree.ElementTree as ET

from templates import ERROR_PAGE_TEMPLATE, SUCCESS_PAGE_TEMPLATE, WAITING_PAGE_TEMPLATE

logger = logging.getLogger(__name__)

# SAML namespace URI (saml2 and saml share the same URI)
SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"


@dataclass
class SAMLResponse:
    """Container for parsed SAML response data.

    Attributes:
        raw_response: Base64-encoded SAML response as received from the IdP.
        decoded_xml: The decoded XML string of the SAML response.
        assertion: The base64-encoded SAML assertion element, if extracted.
        relay_state: The RelayState value from the SAML POST, if present.
        attributes: Parsed SAML attribute name/value pairs.  Each key maps
            to a list of values to support multi-valued attributes (e.g.
            multiple roles).
    """

    raw_response: str
    decoded_xml: str
    assertion: Optional[str] = None
    relay_state: Optional[str] = None
    attributes: dict[str, list[str]] = field(default_factory=dict)

    @property
    def assertion_xml(self) -> Optional[str]:
        """Decode and return the assertion as raw XML, or ``None`` if absent."""
        if self.assertion is None:
            return None
        return base64.b64decode(self.assertion).decode("utf-8")


class SAMLHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the SAML authentication flow.

    Serves a waiting page on GET and processes the SAML POST callback
    from AWS IAM Identity Center on the ``/saml/acs`` endpoint.

    Class-level attributes are used to share state with the owning
    :class:`SAMLServer` because ``http.server`` instantiates a new
    handler per request.
    """

    saml_result: Optional[SAMLResponse] = None
    shutdown_event: Optional[threading.Event] = None

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Route request log messages through the ``logging`` module."""
        logger.info(args[0])

    def do_GET(self) -> None:
        """Handle GET requests.

        Routes:
            ``/`` or ``/health`` — serve the waiting page.
            ``/status`` — return JSON polling endpoint.
            Everything else — 404.
        """
        if self.path in ("/", "/health"):
            self._send_waiting_page()
        elif self.path == "/status":
            self._send_status()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        """Handle POST requests.

        Routes:
            ``/saml/acs`` or ``/saml`` — process the SAML response callback.
            Everything else — 404.
        """
        if self.path in ("/saml/acs", "/saml"):
            self._handle_saml_response()
        else:
            self.send_error(404, "Not Found")

    def _send_waiting_page(self) -> None:
        """Send the waiting page with a spinner and auto-polling script."""
        self._send_html_response(WAITING_PAGE_TEMPLATE)

    def _send_status(self) -> None:
        """Return a JSON object indicating whether a SAML response has arrived.

        Response body::

            {"status": "received"|"waiting", "has_saml_response": bool}
        """
        status: dict[str, str | bool] = {
            "status": "received" if SAMLHandler.saml_result else "waiting",
            "has_saml_response": SAMLHandler.saml_result is not None,
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(status).encode())

    def _handle_saml_response(self) -> None:
        """Decode and store the SAML response received from AWS SSO.

        Reads the POST body, extracts the ``SAMLResponse`` and optional
        ``RelayState`` parameters, parses attributes from the assertion,
        and sends a success or error page back to the browser.  On success,
        schedules a delayed server shutdown.
        """
        content_length: int = int(self.headers.get("Content-Length", 0))
        post_data: str = self.rfile.read(content_length).decode("utf-8")

        params: dict[str, list[str]] = urllib.parse.parse_qs(post_data)
        saml_response_b64: str | None = params.get("SAMLResponse", [None])[0]
        relay_state: str | None = params.get("RelayState", [None])[0]

        if not saml_response_b64:
            self._send_error_page("No SAMLResponse found in POST data")
            return

        try:
            decoded_xml: str = base64.b64decode(saml_response_b64).decode("utf-8")
            attributes: dict[str, list[str]] = _parse_saml_attributes(decoded_xml)
            assertion: str | None = _extract_assertion(decoded_xml)

            SAMLHandler.saml_result = SAMLResponse(
                raw_response=saml_response_b64,
                decoded_xml=decoded_xml,
                assertion=assertion,
                relay_state=relay_state,
                attributes=attributes,
            )

            logger.info("SAML Response received!")
            if attributes:
                logger.info("Parsed %d attributes", len(attributes))

            self._send_success_page(attributes, relay_state)

            if SAMLHandler.shutdown_event:
                threading.Thread(target=self._delayed_shutdown, daemon=True).start()

        except Exception as e:
            logger.error("Failed to process SAML response: %s", e)
            self._send_error_page(f"Failed to process SAML response: {e}")

    def _delayed_shutdown(self) -> None:
        """Signal server shutdown after a brief delay so the HTTP response can flush."""
        time.sleep(0.5)
        logger.info("Shutting down...")
        SAMLHandler.shutdown_event.set()

    def _send_success_page(
        self, attributes: dict[str, list[str]], relay_state: Optional[str]
    ) -> None:
        """Render and send the success page with parsed SAML attributes.

        All dynamic values are passed through ``html.escape()`` before
        insertion into the template to prevent XSS — it converts characters
        like ``<``, ``>``, ``&``, and ``"`` into safe HTML entity equivalents.
        """
        attr_table = ""
        if attributes:
            rows = ""
            for key, values in attributes.items():
                escaped_values = "<br>".join(html.escape(v) for v in values)
                rows += (
                    f"<tr><td><strong>{html.escape(key)}</strong></td>"
                    f"<td>{escaped_values}</td></tr>"
                )
            attr_table = (
                "<h2>SAML Attributes</h2>"
                "<table><tr><th>Attribute</th><th>Value</th></tr>"
                f"{rows}</table>"
            )

        page = SUCCESS_PAGE_TEMPLATE.substitute(
            attr_table=attr_table,
            relay_state=html.escape(relay_state or "N/A"),
        )
        self._send_html_response(page)

    def _send_error_page(self, error_message: str) -> None:
        """Render and send an error page with the given message."""
        page = ERROR_PAGE_TEMPLATE.substitute(
            error_message=html.escape(error_message),
        )
        self._send_html_response(page, status=400)

    def _send_html_response(self, content: str, status: int = 200) -> None:
        """Write an HTML response with security headers.

        Args:
            content: The HTML body to send.
            status: HTTP status code (default 200).
        """
        encoded: bytes = content.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(encoded))
        self.send_header(
            "Content-Security-Policy", "default-src 'self' 'unsafe-inline'"
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(encoded)


def _extract_assertion(xml_string: str) -> Optional[str]:
    """Extract the ``<Assertion>`` element from a SAML response and base64-encode it.

    Returns the assertion as a base64-encoded string ready for use with SPs
    that accept a standalone assertion (e.g. ``AssumeRoleWithSAML``), or
    ``None`` if no assertion element is found.

    Args:
        xml_string: Decoded XML body of the SAML response.

    Returns:
        The ``<Assertion>`` element as a base64-encoded string, or ``None``.
    """
    try:
        root = ET.fromstring(xml_string)
        assertion_elem = root.find(f".//{{{SAML_ASSERTION_NS}}}Assertion")
        if assertion_elem is not None:
            assertion_xml = ET.tostring(assertion_elem, encoding="unicode")
            return base64.b64encode(assertion_xml.encode("utf-8")).decode("ascii")
    except ET.ParseError as e:
        logger.warning("Could not extract SAML assertion: %s", e)
    return None


def _parse_saml_attributes(xml_string: str) -> dict[str, list[str]]:
    """Extract attribute name/value pairs from a SAML assertion XML string.

    Searches for ``<Attribute>`` elements in the SAML 2.0 assertion namespace
    and returns a mapping of simplified attribute names to lists of their
    values.  Multi-valued attributes (e.g. multiple roles) are fully preserved.
    Attribute names that contain ``/`` are shortened to the last segment
    (e.g. ``https://…/Role`` becomes ``Role``).

    Args:
        xml_string: Decoded XML body of the SAML response.

    Returns:
        Mapping of attribute short-names to lists of text values.
    """
    attributes: dict[str, list[str]] = {}
    try:
        root = ET.fromstring(xml_string)
        ns = SAML_ASSERTION_NS

        for attr in root.findall(f".//{{{ns}}}Attribute"):
            name = attr.get("Name", "")
            simple_name = name.rsplit("/", 1)[-1] if "/" in name else name
            values = [
                elem.text
                for elem in attr.findall(f"{{{ns}}}AttributeValue")
                if elem.text
            ]
            if values:
                attributes.setdefault(simple_name, []).extend(values)
    except ET.ParseError as e:
        logger.warning("Could not parse SAML XML: %s", e)

    return attributes


def _validate_url(url: str) -> bool:
    """Return ``True`` if *url* has an http(s) scheme and a non-empty host.

    Args:
        url: The URL string to validate.

    Returns:
        ``True`` when the URL is well-formed with an HTTP(S) scheme.
    """
    parsed: urllib.parse.ParseResult = urllib.parse.urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


class SAMLServer:
    """Manages the lifecycle of the local SAML authentication server.

    Starts a :class:`socketserver.TCPServer` that listens for the SAML POST
    callback on ``localhost``, optionally opens the user's browser to the SSO
    URL, and blocks until a response is received or the timeout expires.

    The server always binds to ``localhost`` to ensure traffic never leaves
    the machine.
    """

    DEFAULT_TIMEOUT: int = 300  # 5 minutes
    _HOST: str = "localhost"

    def __init__(self, port: int = 8443) -> None:
        self.port: int = port
        self.server: Optional[socketserver.TCPServer] = None
        self.shutdown_event: threading.Event = threading.Event()

    @property
    def callback_url(self) -> str:
        """URL that AWS SSO should redirect to."""
        return f"http://{self._HOST}:{self.port}/saml/acs"

    def start(
        self,
        sso_url: str,
        open_browser: bool = True,
        wait: bool = True,
        timeout: Optional[int] = None,
    ) -> Optional[SAMLResponse]:
        """Start the SAML authentication flow.

        Args:
            sso_url: AWS SSO login URL
            open_browser: Whether to automatically open the browser
            wait: Whether to wait for SAML response before returning
            timeout: Seconds to wait before giving up (None = DEFAULT_TIMEOUT)

        Returns:
            SAMLResponse if wait=True and authentication succeeds, None otherwise
        """
        SAMLHandler.saml_result = None
        SAMLHandler.shutdown_event = self.shutdown_event

        socketserver.TCPServer.allow_reuse_address = True

        try:
            self.server = socketserver.TCPServer((self._HOST, self.port), SAMLHandler)
        except OSError as e:
            logger.error("Cannot start server on port %d: %s", self.port, e)
            return None

        logger.info("Starting SAML server on http://%s:%d", self._HOST, self.port)
        logger.info("Callback URL: %s", self.callback_url)

        logger.info("SSO URL:\n  %s\n", sso_url)

        if open_browser:
            logger.info("Opening browser automatically...")
            logger.info("If browser doesn't open, click the link above.\n")
            webbrowser.open(sso_url)

        logger.info("Please complete authentication in your browser...\n")

        original_sigint = signal.getsignal(signal.SIGINT)

        def signal_handler(_sig, _frame):
            logger.info("Interrupted — shutting down...")
            self.shutdown_event.set()

        signal.signal(signal.SIGINT, signal_handler)

        try:
            if wait:
                return self._run_and_wait(timeout)
            else:
                threading.Thread(target=self.server.serve_forever, daemon=True).start()
                return None
        finally:
            signal.signal(signal.SIGINT, original_sigint)

    def _run_and_wait(self, timeout: Optional[int]) -> Optional[SAMLResponse]:
        """Run the server and block until a SAML response arrives or *timeout* elapses.

        Args:
            timeout: Maximum seconds to wait. Falls back to :attr:`DEFAULT_TIMEOUT`
                     when ``None``.

        Returns:
            The captured :class:`SAMLResponse`, or ``None`` on timeout.
        """
        effective_timeout = timeout if timeout is not None else self.DEFAULT_TIMEOUT

        server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        server_thread.start()

        timed_out = not self.shutdown_event.wait(timeout=effective_timeout)

        self.server.shutdown()
        self.server.server_close()

        if timed_out and SAMLHandler.saml_result is None:
            logger.error(
                "Timed out after %d seconds waiting for SAML response.",
                effective_timeout,
            )
            return None

        return SAMLHandler.saml_result

    def stop(self) -> None:
        """Stop the server and release the listening socket.

        Safe to call multiple times or when the server was never started.
        """
        self.shutdown_event.set()
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass


def save_saml_response(response: SAMLResponse, output_file: str) -> None:
    """Persist a :class:`SAMLResponse` to a JSON file.

    The JSON contains the base64-encoded SAML response, the decoded XML,
    the relay state, and the parsed attribute dictionary.  The file is
    created with mode ``0o600`` (owner read/write only) because the SAML
    assertion is a short-lived bearer credential.

    Args:
        response: The captured SAML response to save.
        output_file: Destination file path.
    """
    data = {
        "saml_response": response.raw_response,
        "decoded_xml": response.decoded_xml,
        "assertion": response.assertion,
        "relay_state": response.relay_state,
        "attributes": response.attributes,
    }
    try:
        fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("SAML response saved to: %s", output_file)
    except OSError as e:
        logger.error("Failed to save SAML response to %s: %s", output_file, e)


def main() -> int:
    """CLI entry point — parse arguments, run the server, and handle output.

    Returns:
        Exit code: ``0`` on success, ``1`` on failure.
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Local SAML assertion capture server for AWS IAM Identity Center",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--sso-url",
        required=True,
        help="AWS SSO login URL (e.g., https://your-portal.awsapps.com/start/#/saml/...)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="Local server port (default: 8443)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Don't automatically open browser",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Save SAML response to JSON file",
    )
    parser.add_argument(
        "--print-saml",
        action="store_true",
        help="Print decoded SAML XML to stdout",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=SAMLServer.DEFAULT_TIMEOUT,
        help=f"Seconds to wait for authentication (default: {SAMLServer.DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress informational output",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug-level output",
    )

    args: argparse.Namespace = parser.parse_args()

    # Configure logging
    level: int
    if args.quiet:
        level = logging.WARNING
    elif args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        format="[%(levelname)s] %(asctime)s — %(message)s",
        datefmt="%H:%M:%S LT",
        level=level,
    )

    # Validate SSO URL
    if not _validate_url(args.sso_url):
        logger.error("Invalid SSO URL: %s", args.sso_url)
        return 1

    server: SAMLServer = SAMLServer(port=args.port)

    print("=" * 60)
    print("  AWS IAM Identity Center — SAML Capture Server")
    print("=" * 60)
    print()

    response: SAMLResponse | None = server.start(
        sso_url=args.sso_url,
        open_browser=not args.no_browser,
        wait=True,
        timeout=args.timeout,
    )

    if response:
        print("\n" + "=" * 60)
        print("  Authentication Complete!")
        print("=" * 60)

        if response.attributes:
            print("\nSAML Attributes:")
            for key, values in response.attributes.items():
                if len(values) == 1:
                    print(f"  {key}: {values[0]}")
                else:
                    print(f"  {key}:")
                    for v in values:
                        print(f"    - {v}")

        if args.print_saml:
            print("\nDecoded SAML Response:")
            print("-" * 40)
            print(response.decoded_xml)

        if args.output:
            save_saml_response(response, args.output)

        print("\n[Done] SAML assertion is ready for use.")
        return 0
    else:
        print("\n[Error] No SAML response received.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
