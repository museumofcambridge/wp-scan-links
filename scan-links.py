#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pymysql>=1.1.0",
#     "requests>=2.31.0",
#     "rich>=13.0.0",
# ]
# ///
"""
Scan WordPress posts and pages for external URLs and embeds.

Usage:
    uv run scan-links.py [options]

    --wp-config FILE      Path to wp-config.php (default: next to this script)
    --output FILE.html    Write results to HTML file (default: console)
    --test                Test each URL for accessibility and embed permissions
    --timeout N           HTTP timeout in seconds (default: 10)

Detects:
  - Regular external URLs (href, src, action attributes, CSS url())
  - Embed URLs (iframe src, embed src, object data)

When testing embeds, checks that:
  - The resource exists (HTTP 200)
  - Embedding is allowed (X-Frame-Options and CSP headers)

Interrupt testing with Ctrl+C — partial results will still be output.
"""

import argparse
import html as html_lib
from http import HTTPStatus
import re
import signal
import sys
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import ssl as _ssl

import pymysql
import pymysql.cursors
import requests
from requests.exceptions import (
    RequestException,
    ConnectionError as RequestsConnectionError,
    SSLError as RequestsSSLError,
    ConnectTimeout,
    ReadTimeout,
    Timeout,
    TooManyRedirects,
)
from rich.console import Console

console = Console(stderr=True)


def parse_wp_config(config_path: Path) -> dict:
    """
    Parse DB constants and table prefix from a wp-config.php file.
    Follows local include: if local/wp-config.php exists alongside the main
    file, parse it first so its defines take precedence (matching PHP behaviour).
    """
    define_re = re.compile(
        r"""define\s*\(\s*['"](\w+)['"]\s*,\s*['"]([^'"]*)['"]\s*\)""",
        re.IGNORECASE,
    )
    prefix_re = re.compile(r"""\$table_prefix\s*=\s*['"]([^'"]+)['"]\s*;""")

    values: dict[str, str] = {}

    def _parse_file(path: Path) -> None:
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in define_re.finditer(text):
            key, val = m.group(1), m.group(2)
            if key not in values:
                values[key] = val
        if "table_prefix" not in values:
            m = prefix_re.search(text)
            if m:
                values["table_prefix"] = m.group(1)

    # Check for local override (mirrors the PHP include logic)
    local_config = config_path.parent / "local" / "wp-config.php"
    if local_config.exists():
        _parse_file(local_config)

    _parse_file(config_path)
    return values

# Match href/src attributes and CSS url() values containing absolute URLs
URL_PATTERNS = [
    re.compile(r'''(?:href|src|action)\s*=\s*["'](https?://[^"']+)["']''', re.IGNORECASE),
    re.compile(r'''url\(["']?(https?://[^"')]+)["']?\)''', re.IGNORECASE),
    # Match bare URLs (on their own line or surrounded by whitespace)
    re.compile(r'(?:^|\s)(https?://[^\s<>"{}|\\^`\[\]]+)(?:\s|$)', re.MULTILINE),
]

# Match URLs in embed-specific attributes (data for <object>, src for <iframe>/<embed>)
EMBED_PATTERNS = [
    re.compile(r'''<iframe[^>]+src\s*=\s*["'](https?://[^"']+)["']''', re.IGNORECASE),
    re.compile(r'''<embed[^>]+src\s*=\s*["'](https?://[^"']+)["']''', re.IGNORECASE),
    re.compile(r'''<object[^>]+data\s*=\s*["'](https?://[^"']+)["']''', re.IGNORECASE),
    # Match bare URLs used as embeds
    re.compile(r'(?:^|\s)(https?://[^\s<>"{}|\\^`\[\]]+)(?:\s|$)', re.MULTILINE),
]

_TITLE_RE = re.compile(r'<title[^>]*>([^<]{1,200})</title>', re.IGNORECASE)

_interrupted = False

# Domains that require a real browser session (Cloudflare, login walls, etc.)
# URLs on these domains are listed but not tested.
BROWSER_ONLY_DOMAINS = {
    "ancestry.com",
    "ancestry.co.uk",
    "ancestry.com.au",
    "ancestry.ca",
    "ancestry.ie",
    "ancestry.de",
    "ancestry.fr",
    "ancestry.it",
    "ancestry.se",
    "ancestry.no",
    "ancestry.dk",
    "ancestry.mx",
    "sciencedirect.com",
    "freepages.rootsweb.com",
    # wikipedia links can be tested however there are a large nunber
    # of them so we hit 429 (rate limiting) quickly. Since wikipedia
    # links are persistent and reliable then we don't need to test them
    "en.wikipedia.org",
    # cemetery links can be tested however there are a large number of
    # them. No rate limiting is done but we don't want to stress the
    # site and the links are persistent and reliable
    "millroadcemetery.org.uk",
    # historicengland uses cloudflare protectoin so can't be checked
    # by the script
    "historicengland.org.uk",
    # archive.org refuses connections agter a few fetches and links
    # there are stable so don't need testing
    "web.archive.org",
}


def _is_browser_only(url: str) -> bool:
    host = urlparse(url).netloc.lower().split(":")[0].removeprefix("www.")
    return host in BROWSER_ONLY_DOMAINS or any(
        host.endswith("." + d) for d in BROWSER_ONLY_DOMAINS
    )


# Markers found in Cloudflare JS/managed-challenge response bodies
CF_CHALLENGE_MARKERS = (
    "just a moment",
    "__cf_chl",
    "cf_chl_opt",
    "challenge-platform",
    "/cdn-cgi/challenge-platform",
)


def _is_cf_challenge(resp, body: str = "") -> bool:
    """True if resp is a Cloudflare interstitial/JS challenge (403 or 503).

    Pass a pre-read `body` string when the caller has already consumed the
    response stream. When omitted, reads up to 4 KB (safe on HEAD — returns "").
    """
    if resp.status_code not in (403, 503):
        return False
    if "cloudflare" not in resp.headers.get("server", "").lower():
        return False
    if resp.headers.get("cf-mitigated", "").lower() == "challenge":
        return True
    if not body:
        try:
            body = resp.raw.read(4096, decode_content=True).decode("utf-8", "replace")
        except Exception:
            body = ""
    return any(m in body.lower() for m in CF_CHALLENGE_MARKERS)


def _extract_403_reason(body: str) -> str | None:
    """Extract a short human-readable reason from a 403 response body.

    Tries the <title> tag; strips generic/redundant terms so only the
    site-specific part remains (e.g. 'JSTOR: Access Check', 'Peterhouse').
    Returns None when nothing informative is found.
    """
    m = _TITLE_RE.search(body)
    if not m:
        return None
    title = html_lib.unescape(m.group(1)).strip()
    # Remove noise: leading/trailing code/phrase, pipe-separated site names, etc.
    title = re.sub(r'^\s*403\s*[-–|:]*\s*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\b(forbidden|error)\b[\s\-–|:]*', '', title, flags=re.IGNORECASE)
    title = re.sub(r'\s+', ' ', title).strip(' -–|:')
    return title[:80] if title else None


def _handle_interrupt(sig, frame):
    global _interrupted
    console.print("\n[yellow]Interrupted — saving results so far...[/yellow]")
    _interrupted = True


def get_connection(cfg: dict):
    return pymysql.connect(
        host=cfg["DB_HOST"],
        user=cfg["DB_USER"],
        password=cfg["DB_PASSWORD"],
        database=cfg["DB_NAME"],
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )


def get_site_url(conn, prefix) -> str:
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT option_value FROM {prefix}options WHERE option_name = 'siteurl'"
        )
        row = cur.fetchone()
        if not row or not row["option_value"]:
            console.print("[red]Error:[/red] siteurl not found in wp_options.")
            sys.exit(1)
        return row["option_value"].rstrip("/")


def fetch_posts(conn, prefix):
    with conn.cursor() as cur:
        cur.execute(f"""
            SELECT ID, post_title, post_type, post_content
            FROM {prefix}posts
            WHERE post_status = 'publish'
              AND post_type IN ('post', 'page')
            ORDER BY ID
        """)
        return cur.fetchall()


def _strip_url_punct(url: str) -> str:
    """Strip trailing punctuation, keeping ) when it closes an unmatched (."""
    while True:
        prev = url
        url = url.rstrip(".,;")
        if url.endswith(")") and url.count("(") < url.count(")"):
            url = url[:-1]
        if url == prev:
            break
    return url


def extract_urls(content):
    urls = set()
    for pattern in URL_PATTERNS:
        for m in pattern.finditer(content or ""):
            urls.add(_strip_url_punct(m.group(1)))
    return urls


def extract_embed_urls(content):
    """Extract URLs used for embedding (iframe, embed, object)."""
    urls = set()
    for pattern in EMBED_PATTERNS:
        for m in pattern.finditer(content or ""):
            urls.add(_strip_url_punct(m.group(1)))
    return urls


def is_external(url, site_host):
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
        return bool(host) and host != site_host
    except Exception:
        return False


def collect_urls(posts, site_url, site_host):
    """Return sorted list of (url, [(post_id, title, post_url, is_embed), ...])."""
    url_refs: dict[str, list] = defaultdict(list)
    for post in posts:
        post_url = f"{site_url}/?p={post['ID']}"
        ref_base = (post["ID"], post["post_title"] or f"(ID {post['ID']})", post_url)

        # Collect regular URLs
        for url in extract_urls(post["post_content"]):
            if is_external(url, site_host):
                ref = ref_base + (False,)  # False = not an embed
                if ref not in url_refs[url]:
                    url_refs[url].append(ref)

        # Collect embed URLs
        for url in extract_embed_urls(post["post_content"]):
            if is_external(url, site_host):
                ref = ref_base + (True,)  # True = is an embed
                if ref not in url_refs[url]:
                    url_refs[url].append(ref)

    return sorted(url_refs.items())


def _classify_error(exc: RequestException) -> str:
    """Return a short, human-readable description of a requests exception."""
    if isinstance(exc, ConnectTimeout):
        return "Connect timeout"
    if isinstance(exc, ReadTimeout):
        return "Read timeout"
    if isinstance(exc, Timeout):
        return "Timeout"
    if isinstance(exc, TooManyRedirects):
        return "Too many redirects"

    msg = str(exc)

    if isinstance(exc, RequestsSSLError):
        # Extract the human-readable part after the [SSL: REASON] code:
        # e.g. "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1006)"
        m = re.search(r'\[SSL: [A-Z_]+\]\s*([^(]+?)(?:\s*\(_ssl\.c|$)', msg)
        if m:
            detail = m.group(1).strip().rstrip("')")
            if detail:
                return f"SSL: {detail}"
        # Fallback: look for the ssl.SSLError in the exception chain
        cause = exc.__context__
        while cause is not None:
            if isinstance(cause, _ssl.SSLError) and cause.reason:
                return f"SSL: {cause.reason.replace('_', ' ').lower()}"
            cause = getattr(cause, "__context__", None)
        return "SSL error"

    if isinstance(exc, RequestsConnectionError):
        if any(x in msg for x in (
            "nodename nor servname provided",
            "Name or service not known",
            "getaddrinfo failed",
            "No address associated with hostname",
            "Temporary failure in name resolution",
        )):
            return "DNS failure: host not found"
        if "Connection refused" in msg:
            return "Connection refused"
        if "RemoteDisconnected" in msg or "Connection reset by peer" in msg:
            return "Connection reset by server"
        if "timed out" in msg.lower():
            return "Connection timed out"
        m = re.search(r"Failed to establish a new connection:\s*(.+?)(?:'\)|\"|$)", msg)
        if m:
            return f"Connection failed: {m.group(1).strip()[:80]}"
        return "Connection error"

    return str(exc)[:120]


def test_url(url, timeout):
    """Returns (status_code_or_None, error_string_or_None, note_or_None)."""
    headers = {"User-Agent": "Mozilla/5.0 (compatible; link-checker/1.0)"}

    def _fetch(u):
        try:
            resp = requests.head(u, timeout=timeout, allow_redirects=True, headers=headers)
            if resp.status_code in (403, 405, 503):
                # Fast CF detection from HEAD headers (no body on HEAD).
                if _is_cf_challenge(resp):
                    return None, None, "Cloudflare challenge"
                # Fallback to GET for servers that reject/misbehave on HEAD.
                resp = requests.get(
                    u, timeout=timeout, allow_redirects=True, headers=headers, stream=True
                )
                # Read body once — used for CF detection and 403 reason extraction.
                body = ""
                if resp.status_code in (403, 503):
                    try:
                        body = resp.raw.read(4096, decode_content=True).decode("utf-8", "replace")
                    except Exception:
                        pass
                resp.close()
                if _is_cf_challenge(resp, body):
                    return None, None, "Cloudflare challenge"
                note = _extract_403_reason(body) if resp.status_code == 403 else None
                return resp.status_code, None, note
            return resp.status_code, None, None
        except RequestException as e:
            return None, _classify_error(e), None

    code, error, note = _fetch(url)

    if code == 403 and note is None and url.startswith("http:"):
        https_code, https_error, https_note = _fetch("https:" + url[5:])
        if https_code is not None and 200 <= https_code < 300:
            return 200, None, "HTTPS upgrade required"

    return code, error, note


def _check_embed_allowed(resp, url: str, body: str = "") -> str | None:
    """Check if URL can be embedded based on security headers and content analysis.

    Returns None if embedding is allowed, otherwise returns reason embedding is blocked.
    """
    # Check X-Frame-Options header
    x_frame = resp.headers.get("X-Frame-Options", "").strip().upper()
    if x_frame == "DENY":
        return "X-Frame-Options: DENY"
    if x_frame == "SAMEORIGIN":
        try:
            req_host = urlparse(url).netloc.lower()
            return "X-Frame-Options: SAMEORIGIN (may block if parent differs)"
        except Exception:
            return "X-Frame-Options: SAMEORIGIN"

    # Check Content-Security-Policy frame-ancestors
    csp = resp.headers.get("Content-Security-Policy", "")
    if "frame-ancestors" in csp.lower():
        frame_ancestors = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
        if frame_ancestors:
            policy = frame_ancestors.group(1).strip()
            if policy == "'none'":
                return "CSP frame-ancestors: 'none'"
            # If it doesn't include 'self' or '*' or our site, it might block
            if "'self'" not in policy and "*" not in policy:
                return f"CSP frame-ancestors: {policy[:60]}"

    # Check for sandbox compatibility issues in content
    if not body and hasattr(resp, 'raw'):
        try:
            body = resp.raw.read(16384, decode_content=True).decode("utf-8", "replace")
        except Exception:
            body = ""

    # Look for patterns that commonly break in sandboxed iframes
    if body:
        # Check for postMessage usage (often breaks with origin=null in sandboxes)
        if 'postMessage' in body:
            pass  # postMessage usage is common, but might indicate iframe incompatibility
        # Check for window.parent or window.top access (breaks in sandboxes)
        if re.search(r'window\.(parent|top|opener|frames)', body, re.IGNORECASE):
            return "Page accesses window.parent/top (breaks in sandboxed iframes)"
        # Check for reCAPTCHA (often has sandbox issues)
        if 'recaptcha' in body.lower():
            return "Page uses reCAPTCHA (may fail in sandboxed iframes)"

    return None


def test_embed_url(url, timeout):
    """Test if a URL exists and can be embedded. Returns (status_code_or_None, error_string_or_None, embed_note_or_None)."""
    headers = {"User-Agent": "Mozilla/5.0 (compatible; link-checker/1.0)"}

    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True, headers=headers)
        body = ""

        # For 2xx responses, read body to check for sandbox compatibility issues
        if resp.status_code and 200 <= resp.status_code < 300:
            try:
                get_resp = requests.get(
                    url, timeout=timeout, allow_redirects=True, headers=headers, stream=True
                )
                body = get_resp.raw.read(16384, decode_content=True).decode("utf-8", "replace")
                get_resp.close()
            except Exception:
                pass
        elif resp.status_code in (403, 405, 503):
            # Fallback to GET for servers that reject/misbehave on HEAD
            resp = requests.get(
                url, timeout=timeout, allow_redirects=True, headers=headers, stream=True
            )
            if resp.status_code in (403, 503):
                try:
                    body = resp.raw.read(4096, decode_content=True).decode("utf-8", "replace")
                except Exception:
                    pass
            resp.close()

        # Check if URL exists and can be embedded
        if resp.status_code and 200 <= resp.status_code < 300:
            embed_note = _check_embed_allowed(resp, url, body)
            return resp.status_code, None, embed_note
        else:
            return resp.status_code, None, None
    except RequestException as e:
        return None, _classify_error(e), None


# Codes well-known enough that showing just the number is sufficient.
_COMMON_HTTP_CODES = frozenset({
    200, 201, 204,
    301, 302, 303, 304, 307, 308,
    400, 401, 403, 404, 405, 408, 409, 410, 422, 429,
    500, 501, 502, 503, 504,
})
# Cloudflare-specific codes not in the stdlib HTTPStatus enum.
_EXTRA_STATUS_NAMES = {
    520: "Unknown Error",
    521: "Web Server Down",
    522: "Connection Timed Out",
    523: "Origin Unreachable",
    524: "Timeout Occurred",
    525: "SSL Handshake Failed",
    526: "Invalid SSL Certificate",
    527: "Railgun Error",
    530: "Site Frozen",
}


def _status_reason(code: int) -> str | None:
    """Return a reason phrase for uncommon codes, None for well-known ones."""
    if code in _COMMON_HTTP_CODES:
        return None
    if code in _EXTRA_STATUS_NAMES:
        return _EXTRA_STATUS_NAMES[code]
    try:
        return HTTPStatus(code).phrase
    except ValueError:
        return None


def _status_class(code, error=None):
    if code is None:
        return "fail" if error else "skip"
    if 200 <= code < 300:
        return "ok"
    if 300 <= code < 400:
        return "redirect"
    return "fail"


def _status_label(code, error):
    if error:
        return "ERROR"
    if code is None:
        return "SKIP"
    reason = _status_reason(code)
    return f"{code} {reason}" if reason else str(code)


def esc(s):
    return html_lib.escape(str(s))


# ── Console output ────────────────────────────────────────────────────────────

def print_console_list(url_list, test_results=None):
    for url, refs in url_list:
        if test_results is not None:
            if url in test_results:
                code, error, note = test_results[url]
                if error:
                    status = f"[red]ERROR[/red] [dim]{error}[/dim]"
                elif code is None:
                    status = f"[dim]SKIP ({note})[/dim]"
                else:
                    color = "green" if 200 <= code < 300 else ("yellow" if 300 <= code < 400 else "red")
                    suffix = f" [dim]({note})[/dim]" if note else ""
                    status = f"[{color}]{code}[/{color}]{suffix}"
            else:
                status = "[dim]—[/dim]"
            console.print(f"{status}  [bold]{url}[/bold]")
        else:
            console.print(f"[bold]{url}[/bold]")

        for ref in refs:
            _, title, post_url, *is_embed_list = ref
            is_embed = is_embed_list[0] if is_embed_list else False
            embed_label = " [yellow][EMBED][/yellow]" if is_embed else ""
            console.print(f"     [dim]↳ {title}[/dim]{embed_label}  [blue]{post_url}[/blue]")
        console.print()


# ── HTML output ───────────────────────────────────────────────────────────────

_HTML_STYLE = """
body { font-family: system-ui, -apple-system, sans-serif; font-size: 14px;
       padding: 1.5rem 2rem; color: #222; max-width: 1400px; margin: 0 auto; }
h1 { font-size: 1.25rem; margin-bottom: 0.2rem; }
.meta { color: #666; font-size: 0.85rem; margin-bottom: 1.5rem; }
table { border-collapse: collapse; width: 100%; table-layout: fixed; }
col.url { width: 45%; }
col.status { width: 7%; }
col.refs { width: 48%; }
col.refs-only { width: 55%; }
th { text-align: left; padding: 0.5rem 0.75rem; background: #f0f0f0;
     border-bottom: 2px solid #ccc; position: sticky; top: 0; }
td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #e8e8e8;
     vertical-align: top; word-break: break-all; }
tr.ok td { background: #f6fff6; }
tr.fail td { background: #fff5f5; }
tr.redirect td { background: #fffbe6; }
.ok { color: #1a7a1a; font-weight: bold; }
.fail, .error { color: #c00; font-weight: bold; }
.redirect { color: #8a5a00; font-weight: bold; }
.untested { color: #aaa; }
.skip { color: #888; }
tr.skip td { background: #f8f8f8; }
small { display: block; color: #777; font-size: 0.8em; word-break: break-all; }
a.ext { color: #1155cc; }
a.post { color: #555; font-size: 0.88em; }
a.edit { color: #999; font-size: 0.8em; margin-left: 0.4em; }
a.edit:hover { color: #1155cc; }
.refs { display: flex; flex-direction: column; gap: 2px; }
.ref-item { display: flex; align-items: baseline; gap: 4px; }
.embed-badge { background: #fff3cd; color: #856404; padding: 2px 6px; border-radius: 3px; font-size: 0.75em; font-weight: bold; }
"""

def write_html(url_list, output_file, test_results=None, site_url=None):
    has_test = test_results is not None
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = "WordPress External Links"
    if has_test:
        title += " — Test Results"
    tested_count = len(test_results) if test_results else 0
    fail_count = sum(
        1 for code, err, note in (test_results or {}).values()
        if err or (code is not None and code >= 400)
    )
    skip_count = sum(
        1 for code, err, note in (test_results or {}).values()
        if code is None and not err
    )

    if has_test:
        col_defs = '<col class="url"><col class="status"><col class="refs">'
        header = "<tr><th>URL</th><th>Status</th><th>Referenced By</th></tr>"
    else:
        col_defs = '<col class="url"><col class="refs-only">'
        header = "<tr><th>URL</th><th>Referenced By</th></tr>"

    rows = []
    for url, refs in url_list:
        def _make_ref_html(ref):
            pid, t, pu, is_embed = ref[0], ref[1], ref[2], ref[3] if len(ref) > 3 else False
            embed_badge = '<span class="embed-badge">[EMBED]</span>' if is_embed else ''
            return (
                f'<span class="ref-item">'
                f'<a class="post" href="{esc(pu)}" target="_blank">{esc(t)}</a>'
                f'{embed_badge}'
                f'<a class="edit" href="{esc(site_url)}/wp-admin/post.php?post={pid}&action=edit" target="_blank">(edit)</a>'
                f'</span>'
            )
        ref_html = '<div class="refs">' + "".join(_make_ref_html(ref) for ref in refs) + "</div>"

        if has_test:
            if url not in test_results:
                status_html = '<span class="untested">—</span>'
                row_class = ""
            else:
                code, error, note = test_results[url]
                cls = _status_class(code, error)
                label = _status_label(code, error)
                extra = f"<small>{esc(error[:120])}</small>" if error else (f"<small>{esc(note)}</small>" if note else "")
                status_html = f'<span class="{cls}">{label}</span>{extra}'
                row_class = f' class="{cls}"'
            rows.append(
                f'<tr{row_class}>'
                f'<td><a class="ext" href="{esc(url)}" target="_blank">{esc(url)}</a></td>'
                f'<td>{status_html}</td>'
                f'<td>{ref_html}</td>'
                f"</tr>"
            )
        else:
            rows.append(
                f"<tr>"
                f'<td><a class="ext" href="{esc(url)}" target="_blank">{esc(url)}</a></td>'
                f'<td>{ref_html}</td>'
                f"</tr>"
            )

    meta_parts = [
        f"{len(url_list)} URLs",
        f"site: {esc(site_url)}" if site_url else "",
    ]
    if has_test:
        meta_parts += [f"{tested_count - skip_count} tested", f"{fail_count} failed/error"]
        if skip_count:
            meta_parts.append(f"{skip_count} skipped (browser-only)")
    meta = " &nbsp;·&nbsp; ".join(p for p in meta_parts if p)

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>{_HTML_STYLE}</style>
</head>
<body>
<h1>{esc(title)}</h1>
<p class="meta">Generated {timestamp} &nbsp;·&nbsp; {meta}</p>
<table>
<colgroup>{col_defs}</colgroup>
<thead>{header}</thead>
<tbody>
{"".join(rows)}
</tbody>
</table>
</body>
</html>
"""
    Path(output_file).write_text(page, encoding="utf-8")
    console.print(f"[green]Written:[/green] {output_file}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    signal.signal(signal.SIGINT, _handle_interrupt)

    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="Scan WordPress posts/pages for external URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--wp-config", metavar="FILE",
        default=str(script_dir / "wp-config.php"),
        help="Path to wp-config.php (default: wp-config.php next to this script)",
    )
    parser.add_argument(
        "--output", metavar="FILE.html",
        help="Write results to HTML file (default: console)",
    )
    parser.add_argument(
        "--test", action="store_true",
        help="Test each URL and report HTTP status",
    )
    parser.add_argument(
        "--timeout", type=float, default=10, metavar="SECS",
        help="HTTP request timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    # Load config
    config_path = Path(args.wp_config)
    if not config_path.exists():
        console.print(f"[red]Error:[/red] wp-config.php not found: {config_path}")
        sys.exit(1)
    cfg = parse_wp_config(config_path)
    for key in ("DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME"):
        if key not in cfg:
            console.print(f"[red]Error:[/red] {key} not found in {config_path}")
            sys.exit(1)
    table_prefix = cfg.get("table_prefix", "wp_")

    # Connect and gather data
    conn = get_connection(cfg)
    site_url = get_site_url(conn, table_prefix)
    site_host = urlparse(site_url).netloc.lower().split(":")[0]
    console.print(f"[dim]Site: {site_url}[/dim]")

    posts = fetch_posts(conn, table_prefix)
    console.print(f"[dim]{len(posts)} published posts/pages[/dim]")

    url_list = collect_urls(posts, site_url, site_host)
    conn.close()
    console.print(f"[dim]{len(url_list)} unique external URLs[/dim]\n")

    # Test URLs if requested
    test_results = None
    if args.test:
        test_results = {}
        total = len(url_list)
        console.print(f"Testing {total} URLs (Ctrl+C to stop and save partial results)\n")

        def _domain(url: str) -> str:
            return urlparse(url).netloc.lower()

        def _print_status(code, error, note=None) -> None:
            if error:
                console.print(f"[red]ERROR[/red] [dim]{error}[/dim]")
            elif code is None:
                console.print(f"[dim]SKIP ({note})[/dim]")
            else:
                color = "green" if 200 <= code < 300 else ("yellow" if 300 <= code < 400 else "red")
                label = _status_label(code, None)
                suffix = f" [dim]({note})[/dim]" if note else ""
                console.print(f"[{color}]{label}[/{color}]{suffix}")

        def _has_embed_ref(refs: list) -> bool:
            """Check if any ref is an embed (4th element is True)."""
            return any(len(ref) > 3 and ref[3] for ref in refs)

        queue: deque[tuple] = deque(
            (i, url, refs) for i, (url, refs) in enumerate(url_list)
        )
        retries: list[tuple] = []   # (orig_index, url, refs) deferred due to 429
        deferred_domains: set[str] = set()
        seq = 0  # running count for progress label

        # Phase 1: main queue
        while queue and not _interrupted:
            orig_idx, url, refs = queue.popleft()
            seq += 1
            console.print(f"[dim][{seq}/{total}][/dim] {url} ", end="")

            if _is_browser_only(url):
                console.print("[dim]SKIP (browser-only)[/dim]")
                test_results[url] = (None, None, "browser-only")
                continue

            # Use embed tester if this URL is used for embedding
            if _has_embed_ref(refs):
                code, error, note = test_embed_url(url, args.timeout)
            else:
                code, error, note = test_url(url, args.timeout)

            if code == 429:
                domain = _domain(url)
                deferred_domains.add(domain)
                retries.append((orig_idx, url, refs))
                # Sweep remaining queue: pull out all same-domain entries
                remaining: deque[tuple] = deque()
                for item in queue:
                    (retries if _domain(item[1]) == domain else remaining).append(item)
                queue = remaining
                console.print("[yellow]429 — rate limited, deferred[/yellow]")
            else:
                test_results[url] = (code, error, note)
                _print_status(code, error, note)

        # Phase 2: retry deferred URLs
        if retries and not _interrupted:
            n_domains = len(deferred_domains)
            console.print(
                f"\n[bold]Retrying {len(retries)} deferred URL(s) "
                f"from {n_domains} rate-limited domain(s)[/bold]\n"
            )
            for orig_idx, url, refs in retries:
                if _interrupted:
                    break
                console.print(f"[dim][retry][/dim] {url} ", end="")
                if _has_embed_ref(refs):
                    code, error, note = test_embed_url(url, args.timeout)
                else:
                    code, error, note = test_url(url, args.timeout)
                test_results[url] = (code, error, note)
                _print_status(code, error, note)

        console.print()

    # Output results
    if args.output:
        write_html(url_list, args.output, test_results, site_url)
    else:
        print_console_list(url_list, test_results)


if __name__ == "__main__":
    main()
