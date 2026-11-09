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
- Results sorted by status: failures first (grouped by status code / error), then redirects, skipped and successful URLs
- Every check is recorded in a local SQLite database, so the report can show each failure's history — how many checks in a row it has failed, when it last worked, and whether it's persistent, intermittent or new
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
| `--report-url URL` | `file://` path of `--output` | Where the HTML report is served; shown as the link in the summary |
| `--db FILE` | `~/.local/share/scan-links/history.sqlite` | SQLite database that records every check result (respects `$XDG_DATA_HOME`) |
| `--no-db` | off | Don't record results or show failure history |
| `--persistent N` | `3` | Consecutive failed checks before a failure is flagged as persistent |

## Output

### Console

```
200  https://example.com/some-article
     ↳ My Post Title  https://mysite.com/?p=42

ERROR  DNS failure: host not found
     ↳ Another Post   https://mysite.com/?p=99
```

### Running from cron

When the output isn't a terminal (e.g. under cron), per-URL progress is suppressed, so the emailed output is just the summary and a link to the report:

```sh
uv run scan-links.py --test --output /var/www/html/links.html --report-url https://example.com/links.html
```

```
Site: https://example.com
412 published posts/pages
1873 unique external URLs

Generated 2026-10-19 03:00:12
  1873 URLs
  site: https://example.com
  1702 tested
  41 failed/error
  171 skipped (browser-only)
  12 persistent failures (≥3 consecutive)
Report: https://example.com/links.html
```

### HTML

A self-contained HTML file with a table showing each URL, its HTTP status (color-coded), and the posts that link to it. Each row includes a direct link to the WordPress editor for quick fixing.

With `--test`, rows are grouped by status — errors and 4xx/5xx failures first, then redirects, skipped URLs, and finally successes. Within each group the longest-failing URLs come first.

Each failure shows its history from the database:

- **persistent** — failed at least `--persistent` checks in a row
- **intermittent** — has failed before, recovered, and is failing again
- **new failure** / **first check** — failing for the first time

along with when the current run of failures started, when the URL last worked, and how many of the last 10 checks failed. A *Show only persistent failures* checkbox hides everything else, so you can skip transient problems.

### History database

Each `--test` run adds a row to `runs` and one row per URL to `checks` (`url`, `checked_at`, `outcome` = `ok`/`redirect`/`fail`/`skip`, `status_code`, `error`, `note`). Runs are tagged with the site URL, so one database can serve several sites. Keep it outside the web root — the default location in your home directory is fine for cron.

```sh
sqlite3 ~/.local/share/scan-links/history.sqlite \
  "SELECT checked_at, outcome, status_code, error FROM checks WHERE url = 'https://example.com/x' ORDER BY checked_at"
```

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
