<?php
namespace Grav\Plugin\Grvhulk;

use SQLite3;
use Grav\Common\Filesystem\Folder;

/**
 * SQLite3 database manager for GRVHulk plugin.
 * All methods are static and accept SQLite3 instance as first argument
 * to allow use from both request context and scheduler (separate process).
 */
class HulkDatabase
{
    /** Bump when the schema or a migration changes; gates createSchema(). */
    private const SCHEMA_VERSION = 4;

    private static ?SQLite3 $instance = null;

    public static function getInstance(string $dataDir): SQLite3
    {
        if (self::$instance !== null) {
            return self::$instance;
        }

        if (!is_dir($dataDir)) {
            Folder::create($dataDir);
        }

        $db = new SQLite3($dataDir . '/grvhulk.sqlite');
        $db->enableExceptions(true);
        // Wait for a lock instead of throwing immediately, so a request that
        // hits the DB while the scheduler is writing (VACUUM, bulk swap) does
        // not 500. Applies to request, CLI, and scheduler connections alike.
        $db->busyTimeout(5000);

        self::configurePragmas($db);
        self::createSchema($db);

        self::$instance = $db;
        return $db;
    }

    private static function configurePragmas(SQLite3 $db): void
    {
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA synchronous=NORMAL');
        $db->exec('PRAGMA foreign_keys=ON');
        $db->exec('PRAGMA cache_size=-4000');
    }

    /**
     * Create/migrate the schema. Guarded by PRAGMA user_version so the DDL runs
     * once per version bump instead of on every request (saves locks/IO on the
     * request hot path).
     */
    private static function createSchema(SQLite3 $db): void
    {
        $version = (int)$db->querySingle('PRAGMA user_version');
        if ($version >= self::SCHEMA_VERSION) {
            return;
        }

        $db->exec('
            CREATE TABLE IF NOT EXISTS local (
                ip TEXT PRIMARY KEY,
                reason TEXT DEFAULT \'\',
                is_manual INTEGER NOT NULL DEFAULT 0,
                added_at INTEGER DEFAULT (strftime(\'%s\',\'now\'))
            )
        ');

        $db->exec('
            CREATE TABLE IF NOT EXISTS abuseipdb_bulk (
                ip TEXT PRIMARY KEY,
                confidence INTEGER DEFAULT 0,
                updated_at INTEGER DEFAULT (strftime(\'%s\',\'now\'))
            )
        ');

        $db->exec('
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT NOT NULL,
                source TEXT NOT NULL,
                decision TEXT NOT NULL,
                score INTEGER DEFAULT 0,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (ip, source)
            )
        ');

        $db->exec('
            CREATE TABLE IF NOT EXISTS dark_visitors_agents (
                user_agent TEXT PRIMARY KEY,
                updated_at INTEGER DEFAULT (strftime(\'%s\',\'now\'))
            )
        ');

        $db->exec('
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ');

        // Pending AbuseIPDB reports, flushed by the scheduler so reporting never
        // blocks the request hot path.
        $db->exec('
            CREATE TABLE IF NOT EXISTS report_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                path TEXT NOT NULL DEFAULT \'/\',
                attempts INTEGER NOT NULL DEFAULT 0,
                queued_at INTEGER DEFAULT (strftime(\'%s\',\'now\'))
            )
        ');

        $db->exec('CREATE INDEX IF NOT EXISTS idx_ip_cache_expires ON ip_cache(expires_at)');

        $db->exec('
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT DEFAULT \'\',
                is_manual INTEGER NOT NULL DEFAULT 0,
                acted_at INTEGER DEFAULT (strftime(\'%s\',\'now\'))
            )
        ');

        $db->exec('CREATE INDEX IF NOT EXISTS idx_history_acted_at ON history(acted_at DESC)');

        // Migrations for DBs created before the current version (CREATE IF NOT
        // EXISTS won't alter an existing table):
        //   v2: `local.is_manual`   v3: `report_queue.attempts`   v4: `history`
        self::addColumnIfMissing($db, 'local', 'is_manual', 'INTEGER NOT NULL DEFAULT 0');
        self::addColumnIfMissing($db, 'report_queue', 'attempts', 'INTEGER NOT NULL DEFAULT 0');

        $db->exec('PRAGMA user_version = ' . self::SCHEMA_VERSION);
    }

    private static function addColumnIfMissing(SQLite3 $db, string $table, string $column, string $definition): void
    {
        $result = $db->query("PRAGMA table_info({$table})");
        $found  = false;
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            if (($row['name'] ?? '') === $column) {
                $found = true;
                break;
            }
        }
        $result->finalize();
        if (!$found) {
            $db->exec("ALTER TABLE {$table} ADD COLUMN {$column} {$definition}");
        }
    }

    // --- Local blacklist ---

    public static function isIpInLocal(SQLite3 $db, string $ip, int $ttl = 0): bool
    {
        if ($ttl > 0) {
            // Manual entries never expire; only auto entries are subject to TTL.
            $stmt = $db->prepare('SELECT 1 FROM local WHERE ip = :ip AND (is_manual = 1 OR added_at > :cutoff) LIMIT 1');
            $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
            $stmt->bindValue(':cutoff', time() - $ttl, SQLITE3_INTEGER);
        } else {
            $stmt = $db->prepare('SELECT 1 FROM local WHERE ip = :ip LIMIT 1');
            $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        }
        $result = $stmt->execute();
        return !empty($result->fetchArray(SQLITE3_NUM));
    }

    public static function addIpToLocal(SQLite3 $db, string $ip, string $reason = '', bool $manual = false): void
    {
        // Insert if new. INSERT OR IGNORE never demotes an existing manual entry
        // to auto (an auto add over a manual entry is a no-op). Done as two
        // statements rather than an UPSERT, which would require SQLite 3.24+.
        $stmt = $db->prepare('INSERT OR IGNORE INTO local (ip, reason, is_manual) VALUES (:ip, :reason, :manual)');
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $stmt->bindValue(':reason', $reason, SQLITE3_TEXT);
        $stmt->bindValue(':manual', $manual ? 1 : 0, SQLITE3_INTEGER);
        $stmt->execute();

        $inserted = $db->changes() > 0;

        // A manual add promotes an existing auto entry (and refreshes its reason)
        // so the block becomes exempt from TTL expiry and auto-clean trimming.
        if ($manual) {
            $stmt = $db->prepare('UPDATE local SET is_manual = 1, reason = :reason WHERE ip = :ip');
            $stmt->bindValue(':reason', $reason, SQLITE3_TEXT);
            $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
            $stmt->execute();
        }

        // Record only new blocks to avoid flooding history with repeated auto-hits.
        if ($inserted) {
            self::addHistoryEntry($db, $ip, 'block', $reason, $manual);
        }
    }

    public static function removeIpFromLocal(SQLite3 $db, string $ip): void
    {
        // Fetch existing entry before deleting so we can record the reason.
        $stmt = $db->prepare('SELECT reason, is_manual FROM local WHERE ip = :ip LIMIT 1');
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $result = $stmt->execute();
        $existing = $result->fetchArray(SQLITE3_ASSOC);

        $stmt = $db->prepare('DELETE FROM local WHERE ip = :ip');
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $stmt->execute();

        if ($db->changes() > 0 && $existing) {
            self::addHistoryEntry($db, $ip, 'unblock', $existing['reason'] ?? '', (bool)($existing['is_manual'] ?? false));
        }
    }

    private static function addHistoryEntry(SQLite3 $db, string $ip, string $action, string $reason = '', bool $manual = false): void
    {
        $stmt = $db->prepare('INSERT INTO history (ip, action, reason, is_manual) VALUES (:ip, :action, :reason, :manual)');
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $stmt->bindValue(':action', $action, SQLITE3_TEXT);
        $stmt->bindValue(':reason', $reason, SQLITE3_TEXT);
        $stmt->bindValue(':manual', $manual ? 1 : 0, SQLITE3_INTEGER);
        $stmt->execute();
    }

    /**
     * Prune history entries older than $ttl seconds, then trim to $maxRows if
     * the table still exceeds the cap. Scheduler auto-cleanups (pruneExpiredLocal,
     * trimLocal) intentionally do NOT write history rows — they can remove
     * thousands of IPs at once and would flood the audit log. Only explicit
     * add/remove actions via the admin API or request path are recorded.
     */
    public static function pruneHistory(SQLite3 $db, int $ttl = 2592000, int $maxRows = 50000): int
    {
        $stmt = $db->prepare('DELETE FROM history WHERE acted_at < :cutoff');
        $stmt->bindValue(':cutoff', time() - $ttl, SQLITE3_INTEGER);
        $stmt->execute();
        $pruned = $db->changes();

        // Also cap by row count — delete everything older than the Nth newest
        // row. Resolving the cutoff id once (OFFSET on the indexed PK) avoids a
        // correlated NOT IN subquery scan.
        $cutoffId = $db->querySingle(
            'SELECT id FROM history ORDER BY id DESC LIMIT 1 OFFSET ' . max(0, $maxRows - 1)
        );
        if ($cutoffId !== null) {
            $stmt = $db->prepare('DELETE FROM history WHERE id < :cutoff_id');
            $stmt->bindValue(':cutoff_id', $cutoffId, SQLITE3_INTEGER);
            $stmt->execute();
            $pruned += $db->changes();
        }

        return $pruned;
    }

    public static function getHistory(SQLite3 $db, int $limit = 50, int $offset = 0): array
    {
        $stmt = $db->prepare('SELECT id, ip, action, reason, is_manual, acted_at FROM history ORDER BY id DESC LIMIT :limit OFFSET :offset');
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $stmt->bindValue(':offset', $offset, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $rows = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $rows[] = $row;
        }
        return $rows;
    }

    public static function getHistoryCount(SQLite3 $db): int
    {
        $result = $db->query('SELECT COUNT(1) FROM history');
        return (int)$result->fetchArray(SQLITE3_NUM)[0];
    }

    public static function getLocalCount(SQLite3 $db): int
    {
        $result = $db->query('SELECT COUNT(1) FROM local');
        return (int)$result->fetchArray(SQLITE3_NUM)[0];
    }

    public static function getLastNLocal(SQLite3 $db, int $n = 25): array
    {
        $stmt = $db->prepare('SELECT ip, reason, added_at FROM local ORDER BY rowid DESC LIMIT :n');
        $stmt->bindValue(':n', $n, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $rows = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $rows[] = $row;
        }
        return $rows;
    }

    public static function getLocalPaginated(SQLite3 $db, int $limit = 50, int $offset = 0): array
    {
        $stmt = $db->prepare('SELECT ip, reason, is_manual, added_at FROM local ORDER BY rowid DESC LIMIT :limit OFFSET :offset');
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $stmt->bindValue(':offset', $offset, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $rows = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $rows[] = $row;
        }
        return $rows;
    }

    public static function searchLocal(SQLite3 $db, string $ip): ?array
    {
        $stmt = $db->prepare('SELECT ip, reason, is_manual, added_at FROM local WHERE ip = :ip LIMIT 1');
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        return $row ?: null;
    }

    public static function trimLocal(SQLite3 $db, int $limit): void
    {
        // Only trim auto entries; manual blocks are kept regardless of the limit.
        // Intentionally does not write history rows — see pruneHistory() for rationale.
        $stmt = $db->prepare(
            'DELETE FROM local WHERE is_manual = 0 AND rowid NOT IN (
                SELECT rowid FROM local WHERE is_manual = 0 ORDER BY rowid DESC LIMIT :limit
            )'
        );
        $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        $stmt->execute();
    }

    // --- AbuseIPDB bulk list ---

    public static function isIpInAbuseipdbBulk(SQLite3 $db, string $ip): bool
    {
        $stmt = $db->prepare('SELECT 1 FROM abuseipdb_bulk WHERE ip = :ip LIMIT 1');
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $result = $stmt->execute();
        return !empty($result->fetchArray(SQLITE3_NUM));
    }

    public static function getAbuseipdbBulkCount(SQLite3 $db): int
    {
        $result = $db->query('SELECT COUNT(1) FROM abuseipdb_bulk');
        return (int)$result->fetchArray(SQLITE3_NUM)[0];
    }

    /**
     * Replace the entire bulk list via a staging table, then swap content in a
     * single transaction. The live `abuseipdb_bulk` table is never dropped, so a
     * crash mid-swap can never leave it missing (which would otherwise make the
     * request-path lookup throw). Returns count of inserted IPs.
     */
    public static function replaceBulkList(SQLite3 $db, iterable $ips): int
    {
        $db->exec('CREATE TABLE IF NOT EXISTS abuseipdb_bulk (ip TEXT PRIMARY KEY, confidence INTEGER DEFAULT 0, updated_at INTEGER DEFAULT (strftime(\'%s\',\'now\')))');
        $db->exec('CREATE TABLE IF NOT EXISTS abuseipdb_bulk_staging (ip TEXT PRIMARY KEY, confidence INTEGER DEFAULT 0)');
        $db->exec('DELETE FROM abuseipdb_bulk_staging');

        $count = 0;
        $db->exec('BEGIN');
        $stmt = $db->prepare('INSERT OR IGNORE INTO abuseipdb_bulk_staging (ip, confidence) VALUES (:ip, :conf)');

        // fetchBulkBlacklist() yields plain IP strings (AbuseIPDB plaintext has
        // no per-IP confidence), so iterate values directly.
        foreach ($ips as $ip) {
            $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
            $stmt->bindValue(':conf', 0, SQLITE3_INTEGER);
            $stmt->execute();
            $count++;

            if ($count % 500 === 0) {
                $db->exec('COMMIT');
                $db->exec('BEGIN');
            }
        }
        $db->exec('COMMIT');

        // Swap content in one transaction; readers always see a complete table.
        // Roll back on error so a mid-swap failure can't leave an open
        // transaction or a half-populated table.
        $db->exec('BEGIN IMMEDIATE');
        try {
            $db->exec('DELETE FROM abuseipdb_bulk');
            $db->exec('INSERT INTO abuseipdb_bulk (ip, confidence) SELECT ip, confidence FROM abuseipdb_bulk_staging');
            $db->exec('COMMIT');
        } catch (\Throwable $e) {
            $db->exec('ROLLBACK');
            throw $e;
        }
        $db->exec('DELETE FROM abuseipdb_bulk_staging');

        return $count;
    }

    // --- IP cache (AbuseIPDB live + CrowdSec) ---

    public static function getCachedDecision(SQLite3 $db, string $ip, string $source): ?array
    {
        $stmt = $db->prepare(
            'SELECT decision, score, expires_at FROM ip_cache WHERE ip = :ip AND source = :source AND expires_at > :now LIMIT 1'
        );
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $stmt->bindValue(':source', $source, SQLITE3_TEXT);
        $stmt->bindValue(':now', time(), SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        return $row ?: null;
    }

    public static function setCachedDecision(
        SQLite3 $db,
        string $ip,
        string $source,
        string $decision,
        int $score,
        int $ttl
    ): void {
        $stmt = $db->prepare(
            'INSERT OR REPLACE INTO ip_cache (ip, source, decision, score, expires_at) VALUES (:ip, :source, :decision, :score, :expires)'
        );
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $stmt->bindValue(':source', $source, SQLITE3_TEXT);
        $stmt->bindValue(':decision', $decision, SQLITE3_TEXT);
        $stmt->bindValue(':score', $score, SQLITE3_INTEGER);
        $stmt->bindValue(':expires', time() + $ttl, SQLITE3_INTEGER);
        $stmt->execute();
    }

    public static function pruneExpiredLocal(SQLite3 $db, int $ttl): int
    {
        if ($ttl <= 0) {
            return 0;
        }
        // Never prune manual entries — only auto entries created by URI filters.
        // Intentionally does not write history rows — see pruneHistory() for rationale.
        $stmt = $db->prepare('DELETE FROM local WHERE is_manual = 0 AND added_at <= :cutoff');
        $stmt->bindValue(':cutoff', time() - $ttl, SQLITE3_INTEGER);
        $stmt->execute();
        return $db->changes();
    }

    public static function pruneExpiredCache(SQLite3 $db): void
    {
        $stmt = $db->prepare('DELETE FROM ip_cache WHERE expires_at < :now');
        $stmt->bindValue(':now', time(), SQLITE3_INTEGER);
        $stmt->execute();
    }

    // --- Dark Visitors / Known Agents ---

    public static function isDarkVisitorsAgentBlocked(SQLite3 $db, string $userAgent): bool
    {
        if ($userAgent === '') {
            return false;
        }
        // Push the substring match into SQLite (case-insensitive) so we don't
        // transfer every row into PHP and loop on the request hot path.
        // ESCAPE '\' guards user_agent values that contain LIKE wildcards. The
        // escape character itself must be escaped FIRST, otherwise a stored
        // user_agent containing a backslash would leak a live wildcard.
        $stmt = $db->prepare(
            "SELECT 1 FROM dark_visitors_agents
             WHERE :ua LIKE '%' || REPLACE(REPLACE(REPLACE(user_agent, '\\', '\\\\'), '%', '\\%'), '_', '\\_') || '%' ESCAPE '\\' COLLATE NOCASE
             LIMIT 1"
        );
        $stmt->bindValue(':ua', $userAgent, SQLITE3_TEXT);
        $result = $stmt->execute();
        return !empty($result->fetchArray(SQLITE3_NUM));
    }

    public static function replaceDarkVisitorsAgents(SQLite3 $db, array $agents): void
    {
        $db->exec('BEGIN');
        $db->exec('DELETE FROM dark_visitors_agents');
        $stmt = $db->prepare('INSERT OR IGNORE INTO dark_visitors_agents (user_agent) VALUES (:ua)');
        foreach ($agents as $ua) {
            $ua = trim($ua);
            if ($ua === '' || $ua === '*') {
                continue;
            }
            $stmt->bindValue(':ua', $ua, SQLITE3_TEXT);
            $stmt->execute();
        }
        $db->exec('COMMIT');
    }

    public static function getDarkVisitorsCount(SQLite3 $db): int
    {
        $result = $db->query('SELECT COUNT(1) FROM dark_visitors_agents');
        return (int)$result->fetchArray(SQLITE3_NUM)[0];
    }

    // --- Report queue (async AbuseIPDB reporting) ---

    public static function enqueueReport(SQLite3 $db, string $ip, string $path): void
    {
        $stmt = $db->prepare('INSERT INTO report_queue (ip, path) VALUES (:ip, :path)');
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $stmt->bindValue(':path', substr($path, 0, 500), SQLITE3_TEXT);
        $stmt->execute();
    }

    public static function getPendingReports(SQLite3 $db, int $limit = 100): array
    {
        $stmt = $db->prepare('SELECT id, ip, path FROM report_queue ORDER BY id ASC LIMIT :n');
        $stmt->bindValue(':n', $limit, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $rows = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $rows[] = $row;
        }
        return $rows;
    }

    public static function deleteReport(SQLite3 $db, int $id): void
    {
        $stmt = $db->prepare('DELETE FROM report_queue WHERE id = :id');
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->execute();
    }

    /**
     * Record a failed send: increment the attempt counter and drop the report
     * only once it has exhausted $maxAttempts (so transient API errors are
     * retried on a later flush instead of being lost, while a permanently
     * failing report can't accumulate forever).
     */
    public static function failReport(SQLite3 $db, int $id, int $maxAttempts = 5): void
    {
        $stmt = $db->prepare('UPDATE report_queue SET attempts = attempts + 1 WHERE id = :id');
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->execute();

        $stmt = $db->prepare('DELETE FROM report_queue WHERE id = :id AND attempts >= :max');
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->bindValue(':max', $maxAttempts, SQLITE3_INTEGER);
        $stmt->execute();
    }

    // --- Metadata ---

    public static function getMeta(SQLite3 $db, string $key): ?string
    {
        $stmt = $db->prepare('SELECT value FROM metadata WHERE key = :key LIMIT 1');
        $stmt->bindValue(':key', $key, SQLITE3_TEXT);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_NUM);
        return $row ? $row[0] : null;
    }

    public static function setMeta(SQLite3 $db, string $key, string $value): void
    {
        $stmt = $db->prepare('INSERT OR REPLACE INTO metadata (key, value) VALUES (:key, :value)');
        $stmt->bindValue(':key', $key, SQLITE3_TEXT);
        $stmt->bindValue(':value', $value, SQLITE3_TEXT);
        $stmt->execute();
    }

    // --- Admin stats ---

    public static function getStats(SQLite3 $db, string $dataDir): array
    {
        $dbPath = $dataDir . '/grvhulk.sqlite';
        return [
            'local_count'         => self::getLocalCount($db),
            'history_count'       => self::getHistoryCount($db),
            'abuseipdb_bulk_count' => self::getAbuseipdbBulkCount($db),
            'dark_visitors_count' => self::getDarkVisitorsCount($db),
            'db_size'             => file_exists($dbPath) ? self::humanFilesize(filesize($dbPath)) : '0B',
            'abuseipdb_updated'   => self::getMeta($db, 'abuseipdb_bulk_updated'),
            'dark_visitors_updated' => self::getMeta($db, 'dark_visitors_updated'),
        ];
    }

    private static function humanFilesize(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        while ($bytes >= 1024 && $i < 3) {
            $bytes /= 1024;
            $i++;
        }
        return round($bytes, 1) . $units[$i];
    }
}
