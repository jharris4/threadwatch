"""The one way this package talks HTTP with a credential in hand.

Three things every caller needs and none should reinvent: an opener that
refuses redirects (urlopen follows a 3xx by default and re-sends the
request's headers, Authorization included, to wherever Location points,
so whoever answers a sink, a heartbeat or the Home Assistant API could
collect the bearer token with one 302), a URL reduced to scheme and host
for anything that reaches the journal (Discord, Healthchecks, Uptime
Kuma, Cronitor and Home Assistant all carry the secret in the path, and
Gotify or a basic-auth proxy carries it as user:password before the
host), and free text scrubbed of URLs and credentials before it is
logged. alerts.py grew these for the sinks; the snapshot log fetch and
the availability poll use the same ones.
"""

from __future__ import annotations

import re
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse 3xx answers: a redirect is reported as the HTTP error it is
    and the token stays with the configured host. None of the supported
    targets answers with one."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(NoRedirect())


def urlopen(req: urllib.request.Request, timeout: float):
    """urllib's urlopen, minus redirects. ``timeout`` bounds the connect
    and every socket read, not the whole transfer."""
    return opener.open(req, timeout=timeout)


def redact_url(url: str) -> str:
    """Scheme and host only, for log output."""
    parts = urllib.parse.urlsplit(url)
    if not parts.netloc:
        return "<url>"
    host = parts.netloc.rsplit("@", 1)[-1]
    dropped = parts.path not in ("", "/") or parts.query or host != parts.netloc
    return f"{parts.scheme}://{host}{'/...' if dropped else ''}"


# A URL anywhere in free text, for redact_text.
_URL_IN_TEXT = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>|]+")
# An authentication credential written the way a program prints one: a
# header or a parameter whose name says what it carries, and the rest of
# that line with it (an Authorization value is "Bearer <token>", two
# words), or a bare scheme and its token. curl -v echoes the headers it
# sent; a script written for a sink prints whatever it likes.
_SECRET_KV = re.compile(r"(?i)\b([a-z0-9_.-]*(?:authorization|api[-_]?key|token|secret|"
                        r"password|passwd|auth)[a-z0-9_.-]*)(\s*[:=]\s*)[^\r\n]+")
_SECRET_SCHEME = re.compile(r"(?i)\b(bearer|basic|digest)\s+[^\s\r\n]+")
# Under this many characters, a value expanded from the environment is
# not scrubbed out of free text: a two-character one is a substring of
# ordinary words and would blank the diagnostic instead of the secret.
SCRUB_MIN = 6


def redact_text(text: str, secrets: tuple = ()) -> str:
    """Free text with what must not reach the journal taken out of it:
    every URL reduced to scheme and host, credentials in the shapes above
    blanked, and the exact values in ``secrets`` (a sink's expanded
    ${VAR}s, a token) replaced wherever they appear, which is the only
    way to catch a secret a program prints in a shape nobody can write
    a pattern for."""
    text = _URL_IN_TEXT.sub(lambda m: redact_url(m.group(0)), text)
    text = _SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", text)
    text = _SECRET_SCHEME.sub(lambda m: f"{m.group(1)} <redacted>", text)
    for secret in secrets:
        if len(secret) >= SCRUB_MIN:
            text = text.replace(secret, "<redacted>")
    return text
