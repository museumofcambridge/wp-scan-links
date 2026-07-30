# wp-scan-links

Scan a WordPress site for external URLs and optionally test whether they're still alive.

Reads directly from the WordPress database using credentials from `wp-config.php` — no plugin installation required, works offline, and won't touch the live site.

## Features

- Extracts external URLs from all published posts and pages (`href`, `src`, `action`, CSS `url()`)
- Shows which post/page each URL appears in, with direct links to the WordPress editor
- Optional HTTP testing with colored status codes (2xx / 3xx / 4xx / 5xx / errors)
- Smart error classification: SSL failures, DNS errors, timeouts, connection resets
- Handles rate-limited domains (HTTP 429) — defers and retries them at the end
- Falls back from `HEAD` to `GET` for servers that reject `HEAD`
- Detects HTTP URLs that work on HTTPS and reports them as needing an upgrade
- Outputs to the console (with [Rich](https://github.com/Textualize/rich) formatting) or a self-contained HTML file
- Interrupt with `Ctrl+C` at any time — partial results are saved
- Supports `local/wp-config.php` overrides (mirrors WordPress's own include logic)

## Requirements

- Python 3.11+
- [`uv`](https://docs.astral.sh/uv/) (recommended) — handles dependencies automatically
- MySQL/MariaDB access to your WordPress database

## Usage

The script uses [inline script metadata](https://docs.astral.sh/uv/guides/scripts/) so `uv` installs dependencies automatically on first run.

### List external URLs (console output)

```sh
uv run scan-links.py --wp-config /path/to/wp-config.php
```

### Test every URL and write an HTML report

```sh
uv run scan-links.py --wp-config /path/to/wp-config.php --test --output report.html
```

### Run from the WordPress root (uses wp-config.php next to the script)

```sh
cp scan-links.py /var/www/html/
uv run /var/www/html/scan-links.py --test --output report.html
```

## Options

| Option | Default | Description |
|---|---|---|
| `--wp-config FILE` | `wp-config.php` next to script | Path to your `wp-config.php` |
| `--output FILE.html` | console | Write results to an HTML file |
| `--test` | off | Test each URL and report HTTP status |
| `--timeout SECS` | `10` | HTTP request timeout in seconds |

## Output

### Console

```
200  https://example.com/some-article
     ↳ My Post Title  https://mysite.com/?p=42

ERROR  DNS failure: host not found
     ↳ Another Post   https://mysite.com/?p=99
```

### HTML

A self-contained HTML file with a sortable table showing each URL, its HTTP status (color-coded), and the posts that link to it. Each row includes a direct link to the WordPress editor for quick fixing.

## How it works

1. Parses `wp-config.php` to get database credentials and table prefix
2. Queries `wp_posts` for all published posts and pages
3. Extracts absolute URLs from `href`, `src`, `action` attributes and CSS `url()` values
4. Filters out internal URLs (same host as `siteurl` in `wp_options`)
5. Optionally sends an HTTP `HEAD` request to each URL and reports the status

## Without `uv`

Install dependencies manually and run with Python directly:

```sh
pip install pymysql requests rich
python scan-links.py --wp-config /path/to/wp-config.php
```

## License

See LICENSE
