# GRVHulk — Grav 2 IP Security Plugin

Advanced IP security plugin for [Grav 2](https://getgrav.org/) CMS.  
Blocks malicious IPs using local blacklists, [AbuseIPDB](https://www.abuseipdb.com/), [CrowdSec](https://www.crowdsec.net/), and blocks AI training crawlers via [Known Agents](https://www.knownagents.com/).

## Features

| Feature | Description |
|---------|-------------|
| **Local blacklist** | SQLite-backed list, managed via Admin UI or auto-populated by URI filters |
| **AbuseIPDB bulk** | Nightly download of AbuseIPDB's IP blacklist (free API key required) |
| **AbuseIPDB live** | Per-request confidence-score check with local cache |
| **CrowdSec CTI** | Cloud-based threat intelligence check — no self-hosted agent needed |
| **CrowdSec LAPI** | Self-hosted CrowdSec agent integration (real-time decisions) |
| **AI crawler blocking** | Blocks known AI training crawlers by User-Agent (via Known Agents API) |
| **CIDR whitelist** | IPv4 and IPv6 CIDR ranges that are never blocked |
| **URI filtering** | Regex patterns to auto-blacklist probing IPs (.env, webshells, Log4Shell…) |
| **Admin UI** | Dashboard with stats, IP search/add/remove |
| **Scheduler** | Automated nightly list updates and cleanup |

## Requirements

- Grav 2.0+
- PHP 8.1+
- PHP extensions: `sqlite3`, `curl`
- (Optional) [Grav Admin Plugin](https://github.com/getgrav/grav-plugin-admin) for the UI

## Installation

No `composer install` is needed — GRVHulk relies on `guzzlehttp/guzzle`, which Grav 2 ships as part of its own dependencies.

**Option A — GPM (once listed in the Grav Plugin Repository)**

> GRVHulk is being prepared for the Grav Plugin Repository. Once accepted, install with:

```bash
bin/gpm install grvhulk
```

**Option B — git clone (recommended until GPM listing, easy to update)**

```bash
cd /path/to/grav/user/plugins
git clone https://github.com/horiken1216/grav-plugin-grvhulk.git grvhulk
```

To update later: `git -C grvhulk pull`

**Option C — ZIP download**

1. Download the latest ZIP from the [Releases page](https://github.com/horiken1216/grav-plugin-grvhulk/releases)
2. Extract it into `user/plugins/grvhulk/`

After installing either way, enable the plugin:

- **Admin UI**: Plugins → GRVHulk → toggle on
- **Or manually**: set `enabled: true` in `user/config/plugins/grvhulk.yaml`

> **Development / testing only:** run `composer install` inside the `grvhulk/` directory to install PHPUnit and run the test suite (`composer test`).

## Configuration

Copy `grvhulk.yaml` to `user/config/plugins/grvhulk.yaml` and edit as needed, or configure entirely through the Admin UI.

### Minimum setup — local blacklist only

```yaml
enabled: true
enable_blacklisting: true
sources:
  local: true
```

### With AbuseIPDB (recommended)

```yaml
sources:
  local: true
  abuseipdb_bulk: true   # requires nightly scheduler job

abuseipdb:
  api_key: 'YOUR_KEY'

auto_cache: true   # enable nightly AbuseIPDB refresh
```

Run the scheduler to initialise the bulk list:
```bash
bin/grav scheduler:run
```

### With CrowdSec CTI (cloud)

```yaml
sources:
  crowdsec: true

crowdsec:
  mode: cti
  cti_api_key: 'YOUR_CTI_KEY'
  cti_score_threshold: 3
  cti_cache_ttl: 21600   # 6 hours — stays within free-tier 50 req/day
```

### With CrowdSec LAPI (self-hosted)

```yaml
crowdsec:
  mode: lapi
  lapi_url: 'http://localhost:8080'
  lapi_api_key: 'YOUR_BOUNCER_KEY'   # from: cscli bouncers add grvhulk-bouncer
```

### AI crawler blocking (Known Agents)

```yaml
sources:
  dark_visitors: true

dark_visitors:
  api_key: 'YOUR_KNOWN_AGENTS_KEY'
  agent_types:
    - 'AI Assistant'
    - 'AI Data Scraper'
    - 'AI Search Crawler'
    - 'Undocumented AI Agent'
  cache_ttl: 86400   # refresh once a day
```

### URI filtering

```yaml
enable_filtering: true
filters: |
  wso\.php
  \.env$
  /\.git/config
  \$\{jndi:
```

## Scheduler

Enable the Grav scheduler (cron or system service) for automated list updates and cleanup.

Registered jobs:

| Job | Schedule | Description |
|-----|----------|-------------|
| `grvhulk-auto-clean` | `35 2 * * *` | Trim local blacklist + prune cache + VACUUM |
| `grvhulk-abuseipdb-cache` | `45 2 * * *` | Refresh AbuseIPDB bulk blacklist |
| `grvhulk-dark-visitors` | `0 3 * * *` | Refresh Known Agents UA list |
| `grvhulk-flush-reports` | `*/10 * * * *` | Send queued AbuseIPDB reports (when reporting is enabled) |

Manual trigger:
```bash
bin/grav scheduler:run
```

## Trusted proxies (important behind a CDN / reverse proxy)

By default GRVHulk identifies clients by `REMOTE_ADDR` only. Forwarding headers
(`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`) are **ignored unless the
direct connection comes from a configured trusted proxy** — this prevents
attackers from spoofing their IP to evade blocks or to get a third party blocked.

If your site sits behind Cloudflare, nginx, or a load balancer, list those
proxy IPs/CIDRs so the real client IP is detected:

```yaml
trusted_proxies: |
  173.245.48.0/20
  103.21.244.0/22
  # ...your CDN/proxy ranges
```

Leave it empty for a directly-exposed origin.

## Security Design

- **Spoof-resistant client IP**: forwarding headers are trusted only behind `trusted_proxies` (see above).
- **Fail-open**: if any external API (AbuseIPDB, CrowdSec, Known Agents) is unavailable, or an internal DB check errors, the request is **allowed through** — legitimate visitors are never blocked due to infrastructure failures.
- **Whitelist priority**: whitelisted IPs are always allowed, before any source is checked.
- **SQLite WAL mode + busy timeout**: safe for concurrent PHP-FPM workers and scheduler processes; background maintenance never 500s live requests.
- **CrowdSec CTI quota guard**: if the free-tier daily limit (50 req/day) is exceeded, CTI checks are paused until the next UTC midnight, and transient/quota fail-open results are not cached long-term.
- **Deferred reporting**: AbuseIPDB reports are queued and sent by the scheduler, never synchronously on the request path.
- **Manual blocks persist**: IPs you add by hand are exempt from TTL expiry and auto-clean trimming.

## Emergency CLI Unblock

If you accidentally block your own IP and can no longer reach the admin UI,
use the bundled CLI script over SSH:

```bash
# Run from your Grav root directory
php user/plugins/grvhulk/cli/unblock.php 203.0.113.5

# List the last 25 blocked IPs
php user/plugins/grvhulk/cli/unblock.php --list

# Remove IP and also add it to the whitelist (prevents re-blocking)
php user/plugins/grvhulk/cli/unblock.php 203.0.113.5 --whitelist

# Specify the DB path explicitly (if Grav is not in a standard location)
php user/plugins/grvhulk/cli/unblock.php 203.0.113.5 --db=/path/to/grvhulk.sqlite
```

The script requires no Grav framework — it connects to the SQLite database directly.

## Admin UI

Navigate to **Admin → GRVHulk** to:

- View statistics (blacklist sizes, DB size, last update times)
- Search, add, or remove IPs from the local blacklist
- Access the settings page

## Acknowledgements

GRVHulk is inspired by and built upon the design of
**[grav-plugin-ip-blacklist](https://github.com/aricooperdavis/grav-plugin-ip-blacklist)**
by **Ari Cooper-Davis** (MIT License).

That plugin provided the foundational approach for Grav CMS IP blacklisting,
including the event hook architecture, SQLite storage design, AbuseIPDB integration,
and URI filtering. GRVHulk extends this design for Grav 2 and adds
CrowdSec and AI crawler blocking capabilities.

Thank you, Ari, for the original work. 🙏

## License

MIT — see [LICENSE](LICENSE).
