# Changelog

# v1.0.0
## 06/14/2026

1. [](#new)
    * Initial release
    * Local SQLite blacklist (manual entries + auto-population via URI filters)
    * AbuseIPDB v2 integration:
        * Bulk blacklist (nightly scheduler, streamed to avoid memory limits)
        * Live per-request check with configurable confidence threshold and cache
        * Auto-report of matched IPs to AbuseIPDB
    * CrowdSec integration (dual-mode):
        * CTI cloud API (`cti.api.crowdsec.net`) — no self-hosted agent required
        * LAPI self-hosted agent (`/v1/decisions`)
        * Configurable score threshold and cache TTL
        * Quota guard for CTI free-tier rate limits (50 req/day)
    * Known Agents / Dark Visitors AI crawler blocking:
        * Blocks AI training crawlers by User-Agent
        * Daily update via Grav scheduler
        * Configurable agent type categories
    * CIDR whitelist (IPv4 and IPv6)
    * Trusted-proxy model: forwarding headers (CF-Connecting-IP, X-Real-IP, X-Forwarded-For) are honored only behind a configured `trusted_proxies` CIDR list — otherwise the raw `REMOTE_ADDR` is used, preventing client-IP spoofing
    * URI request filtering with regex patterns (web shells, `.env` probes, credential files, Log4Shell, cloud SSRF, known RCE paths, plus commented context-dependent defaults)
    * Grav Admin UI: statistics dashboard, IP search / add / remove (AJAX)
    * Emergency CLI unblock tool (`cli/unblock.php`), framework-independent
    * SQLite WAL mode for concurrent-access safety
    * Fail-open design — external API failures never block legitimate users
    * Grav 2 / PHP 8.1+ compatible
2. [](#security)
    * Admin JSON API requires an `admin.users`/`admin.super` permission, not just an authenticated session
    * AbuseIPDB reports send the request path only (query string stripped) and are queued for the scheduler — sent asynchronously, retried on transient failure, dropped only after repeated attempts — instead of a synchronous call on the request hot path
    * CrowdSec quota/network fail-open results are no longer cached for the full TTL (only authoritative decisions are cached); CTI lookups are de-duplicated (single-flight) to protect the free-tier quota
    * URI-filter regex runs against a length-capped subject and fails closed on backtracking/recursion limits (ReDoS hardening)
    * SQLite `busy_timeout` plus request-path fail-open so background writes (VACUUM, bulk swap) can't 500 the site; bulk-list refresh swaps content transactionally without dropping the live table
    * Manual blacklist entries are exempt from TTL expiry and auto-clean trimming, and a manual add promotes an existing auto-detected entry
    * Emergency CLI `--whitelist` writes only to the user config (never the shipped default) and handles both block-scalar and list whitelist formats
    * Backslash-correct LIKE escaping for AI-crawler user-agent matching
