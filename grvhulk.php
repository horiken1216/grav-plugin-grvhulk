<?php
namespace Grav\Plugin;

use Composer\Autoload\ClassLoader;
use Grav\Common\Grav;
use Grav\Common\Plugin;
use Grav\Common\Filesystem\Folder;
use Grav\Common\Utils;
use Grav\Framework\Psr7\Response;
use Grav\Plugin\Grvhulk\AbuseIpDbClient;
use Grav\Plugin\Grvhulk\CrowdSecClient;
use Grav\Plugin\Grvhulk\DarkVisitorsClient;
use Grav\Plugin\Grvhulk\HulkDatabase;
use Grav\Plugin\Grvhulk\IpDetector;
use RocketTheme\Toolbox\Event\Event;
use SQLite3;

/**
 * Class GrvhulkPlugin
 *
 * Advanced IP security plugin for Grav 2.
 * Features: local blacklist, AbuseIPDB (bulk + live), CrowdSec (CTI/LAPI),
 * Known Agents AI crawler blocking, CIDR whitelist, URI filtering.
 *
 * Based on the design of grav-plugin-ip-blacklist by Ari Cooper-Davis.
 */
class GrvhulkPlugin extends Plugin
{
    private static ?SQLite3 $dbInstance = null;

    public static function getSubscribedEvents(): array
    {
        return [
            'onPluginsInitialized' => ['onPluginsInitialized', 0],
        ];
    }

    public function autoload(): ClassLoader
    {
        if (file_exists(__DIR__ . '/vendor/autoload.php')) {
            return require __DIR__ . '/vendor/autoload.php';
        }

        // No local vendor — Grav 2 ships guzzlehttp/guzzle, so we only need
        // to register our own namespace with Composer's already-loaded ClassLoader.
        $loader = new ClassLoader();
        $loader->addPsr4('Grav\\Plugin\\Grvhulk\\', [__DIR__ . '/classes/']);
        $loader->register();
        return $loader;
    }

    public function onPluginsInitialized(): void
    {
        // Conditionally load vendor autoload if not already provided by Grav
        if (file_exists(__DIR__ . '/vendor/autoload.php')) {
            require_once __DIR__ . '/vendor/autoload.php';
        }

        $this->enable([
            'onRequestHandlerInit' => ['onRequestHandlerInit', 1000],
            'onSchedulerInitialized' => ['onSchedulerInitialized', 0],
        ]);

        if (!$this->isAdmin() || !$this->grav['user']->authenticated) {
            return;
        }

        $this->enable([
            'onAdminMenu' => ['onAdminMenu', 0],
            'onAdminTwigTemplatePaths' => ['onAdminTwigTemplatePaths', 0],
        ]);
    }

    /**
     * Main request interception hook.
     * $request is the RequestHandlerEvent (or equivalent) that exposes:
     *   - getRoute()->getRoute() for the path
     *   - getRequest()->getParsedBody() for POST data
     *   - setResponse($response) to short-circuit with a custom response
     */
    public function onRequestHandlerInit($request): void
    {
        $config = $this->config();

        // Handle admin JSON API
        try {
            $path = $request->getRoute()->getRoute();
        } catch (\Throwable $e) {
            $path = $_SERVER['REQUEST_URI'] ?? '';
        }

        if ($this->isAdmin() && $this->grav['user']->authenticated && $path === '/admin/grvhulk/data') {
            $this->handleAdminApi($request);
            return;
        }

        // Never block admin area — locking out the admin defeats the purpose of management
        if ($this->isAdmin()) {
            return;
        }

        // Detect client IP (forwarding headers honored only behind trusted proxies)
        $trustedProxies = $this->parseLineList($config['trusted_proxies'] ?? '');
        $ip = IpDetector::getClientIp($trustedProxies);

        // Skip private/reserved IPs (localhost, LAN, etc.)
        if (!IpDetector::isValidPublicIp($ip)) {
            return;
        }

        // Whitelist takes absolute priority
        $whitelist = $this->parseLineList($config['whitelist'] ?? '');
        if (!empty($whitelist) && IpDetector::isWhitelisted($ip, $whitelist)) {
            if ($config['logging'] ?? false) {
                $this->grav['log']->debug("[Hulk] Whitelisted: {$ip}");
            }
            return;
        }

        // Everything below touches the SQLite DB. If a check throws (e.g. the DB
        // is briefly locked by the scheduler), fail OPEN — never 500 a visitor
        // because of an internal error in the security layer.
        try {
            $db = $this->getDb();

            if ($config['enable_blacklisting'] ?? true) {
                // --- Known Agents: User-Agent check ---
                if (!empty($config['sources']['dark_visitors'])) {
                    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
                    if ($ua !== '' && HulkDatabase::isDarkVisitorsAgentBlocked($db, $ua)) {
                        if ($config['logging'] ?? false) {
                            $this->grav['log']->debug("[Hulk] Blocked AI crawler UA: {$ua} ({$ip})");
                        }
                        $this->rejectRequest($request);
                        return;
                    }
                }

                // --- Local blacklist ---
                if (!empty($config['sources']['local'])) {
                    $localTtl = (int)($config['local_ttl'] ?? 86400);
                    if (HulkDatabase::isIpInLocal($db, $ip, $localTtl)) {
                        if ($config['logging'] ?? false) {
                            $this->grav['log']->debug("[Hulk] Blocked by local blacklist: {$ip}");
                        }
                        $this->rejectRequest($request);
                        return;
                    }
                }

                // --- AbuseIPDB bulk blacklist ---
                if (!empty($config['sources']['abuseipdb_bulk'])) {
                    if (HulkDatabase::isIpInAbuseipdbBulk($db, $ip)) {
                        if ($config['logging'] ?? false) {
                            $this->grav['log']->debug("[Hulk] Blocked by AbuseIPDB bulk: {$ip}");
                        }
                        $this->rejectRequest($request);
                        return;
                    }
                }

                // --- CrowdSec check ---
                if (!empty($config['sources']['crowdsec'])) {
                    $mode   = $config['crowdsec']['mode'] ?? 'cti';
                    $source = 'crowdsec_' . $mode;
                    $ttl    = $mode === 'cti'
                        ? (int)($config['crowdsec']['cti_cache_ttl'] ?? 21600)
                        : (int)($config['crowdsec']['lapi_cache_ttl'] ?? 60);
                    $hasKey = $mode === 'cti'
                        ? !empty($config['crowdsec']['cti_api_key'])
                        : !empty($config['crowdsec']['lapi_api_key']);

                    if ($hasKey) {
                        $cached = HulkDatabase::getCachedDecision($db, $ip, $source);
                        if ($cached === null) {
                            // Single-flight: a brief sentinel stops concurrent FPM
                            // workers from all calling the API at once and burning
                            // the CTI free-tier quota (50/day).
                            HulkDatabase::setCachedDecision($db, $ip, $source, 'clean', 0, 10);
                            $client = new CrowdSecClient($config['crowdsec'], $db);
                            $result = $client->checkIp($ip);
                            // Cache only authoritative results; a fail-open "clean"
                            // from a quota lock or network error must not pin a bad
                            // IP as clean for the full TTL (it keeps the 10s sentinel
                            // and is retried shortly).
                            if (!empty($result['cacheable'])) {
                                HulkDatabase::setCachedDecision($db, $ip, $source, $result['decision'], $result['score'], $ttl);
                            }
                            $cached = $result;
                        }
                        if (($cached['decision'] ?? 'clean') === 'block') {
                            if ($config['logging'] ?? false) {
                                $this->grav['log']->debug("[Hulk] Blocked by CrowdSec {$mode} (score:{$cached['score']}): {$ip}");
                            }
                            $this->rejectRequest($request);
                            return;
                        }
                    }
                }
            }

            // --- URI filter ---
            if (!empty($config['enable_filtering'])) {
                $uri = $_SERVER['REQUEST_URI'] ?? '';
                // Cap the subject length to bound regex backtracking (ReDoS) on the
                // request hot path; real probe paths are short.
                $subject = substr($uri, 0, 2048);
                foreach ($this->parseLineList($config['filters'] ?? '') as $filter) {
                    // Escape the delimiter so patterns containing '~' don't break the regex.
                    $pattern = '~' . str_replace('~', '\~', $filter) . '~i';
                    $match   = preg_match($pattern, $subject);
                    if ($match === false) {
                        $err = preg_last_error();
                        if ($err === PREG_BACKTRACK_LIMIT_ERROR || $err === PREG_RECURSION_LIMIT_ERROR) {
                            // Runtime backtracking/recursion failure (possible ReDoS)
                            // — fail closed for this request so a crafted URI cannot
                            // bypass the filter. (Malformed patterns instead surface
                            // as PREG_NO_ERROR/INTERNAL and are skipped below.)
                            if ($config['logging'] ?? false) {
                                $this->grav['log']->error("[Hulk] Regex runtime error (code {$err}) on filter '{$filter}' — failing closed: {$uri}");
                            }
                            if ($config['enable_blacklisting'] ?? true) {
                                $this->rejectRequest($request);
                            }
                            return;
                        }
                        // Invalid pattern (compile error) — skip just this filter.
                        if ($config['logging'] ?? false) {
                            $this->grav['log']->warning("[Hulk] Invalid filter pattern skipped: '{$filter}'");
                        }
                        continue;
                    }
                    if ($match === 1) {
                        if ($config['logging'] ?? false) {
                            $this->grav['log']->debug("[Hulk] URI matched filter '{$filter}': {$uri}");
                        }
                        HulkDatabase::addIpToLocal($db, $ip, 'URI filter: ' . $filter);
                        if (!empty($config['enable_reporting']) && !empty($config['abuseipdb']['api_key'])) {
                            // Queue the report (path only — the query string may carry
                            // secrets) for the scheduler to send, so we never block the
                            // request on a synchronous external API call.
                            $pathOnly = parse_url($uri, PHP_URL_PATH) ?: '/';
                            HulkDatabase::enqueueReport($db, $ip, $pathOnly);
                        }
                        if ($config['enable_blacklisting'] ?? true) {
                            $this->rejectRequest($request);
                        }
                        return;
                    }
                }
            }
        } catch (\Throwable $e) {
            if ($config['logging'] ?? false) {
                $this->grav['log']->error('[Hulk] Security check error, allowing request (fail-open): ' . $e->getMessage());
            }
            return;
        }
    }

    // -------------------------------------------------------------------------
    // Admin JSON API  (POST /admin/grvhulk/data)
    // -------------------------------------------------------------------------

    private function handleAdminApi($request): void
    {
        // Require an admin-level permission, not merely an authenticated session,
        // before any state-changing blacklist action runs.
        $user = $this->grav['user'];
        if (!$user->authorize('admin.users') && !$user->authorize('admin.super')) {
            $request->setResponse(new Response(403, ['Content-Type' => 'application/json'], json_encode(['error' => 'Forbidden'])));
            return;
        }

        try {
            $body = (array)$request->getRequest()->getParsedBody();
        } catch (\Throwable $e) {
            $body = [];
        }

        // CSRF protection: state-changing admin actions require a valid nonce.
        $nonce = $body['admin-nonce'] ?? ($_SERVER['HTTP_X_ADMIN_NONCE'] ?? '');
        if (!Utils::verifyNonce($nonce, 'admin-form')) {
            $request->setResponse(new Response(403, ['Content-Type' => 'application/json'], json_encode(['error' => 'Invalid security token'])));
            return;
        }

        $action  = $body['action'] ?? '';
        $db      = $this->getDb();
        $dataDir = $this->grav['locator']->findResource('user://data', true) . '/grvhulk';

        switch ($action) {
            case 'stats':
                $data = HulkDatabase::getStats($db, $dataDir);
                break;

            case 'last-25':
                $data = HulkDatabase::getLastNLocal($db, 25);
                break;

            case 'search':
                $entry = HulkDatabase::searchLocal($db, $body['ip'] ?? '');
                $data  = ['found' => $entry !== null, 'entry' => $entry];
                break;

            case 'add':
                $ip     = trim($body['ip'] ?? '');
                $reason = trim($body['reason'] ?? 'Manual');
                if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                    $request->setResponse(new Response(400, [], json_encode(['error' => 'Invalid IP address'])));
                    return;
                }
                // Manual entries are exempt from TTL expiry and auto-clean trimming.
                HulkDatabase::addIpToLocal($db, $ip, $reason, true);
                $data = ['success' => true];
                break;

            case 'remove':
                $ip = trim($body['ip'] ?? '');
                HulkDatabase::removeIpFromLocal($db, $ip);
                $data = ['success' => true];
                break;

            default:
                $request->setResponse(new Response(400, [], json_encode(['error' => 'Unknown action: ' . $action])));
                return;
        }

        $request->setResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode($data)));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Parse a multiline string into a trimmed array, skipping blank lines and # comments.
     * Accepts both a plain string (from textarea/editor fields) and an already-decoded array.
     */
    private function parseLineList(mixed $value): array
    {
        if (is_array($value)) {
            return array_values(array_filter(array_map('trim', $value)));
        }
        $lines = explode("\n", (string)$value);
        $result = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line !== '' && $line[0] !== '#') {
                $result[] = $line;
            }
        }
        return $result;
    }

    private function rejectRequest($request): void
    {
        $texts = [
            400 => 'Bad Request',
            403 => 'Forbidden',
            418 => "I'm a teapot",
            503 => 'Service Unavailable',
        ];
        $code     = (int)($this->config()['response'] ?? 403);
        $response = new Response($code, [], $texts[$code] ?? 'Blocked');
        $request->setResponse($response);
    }

    private function getDb(): SQLite3
    {
        if (self::$dbInstance === null) {
            $dataDir         = $this->grav['locator']->findResource('user://data', true) . '/grvhulk';
            self::$dbInstance = HulkDatabase::getInstance($dataDir);
        }
        return self::$dbInstance;
    }

    /**
     * Normalize the agent_types config into a plain list of label strings.
     *
     * Grav's `checkboxes` field with `use: keys` saves data as a `label => bool`
     * map, while hulk.yaml ships a plain list. Accept both and always return a
     * list of selected labels (the shape the Known Agents API expects).
     */
    private static function normalizeAgentTypes($types): array
    {
        $default = ['AI Assistant', 'AI Data Scraper', 'AI Search Crawler', 'Undocumented AI Agent'];
        if (!is_array($types) || $types === []) {
            return $default;
        }
        // Associative map (label => bool) from the admin checkboxes field.
        if (array_keys($types) !== range(0, count($types) - 1)) {
            $selected = array_keys(array_filter($types));
            return $selected !== [] ? $selected : $default;
        }
        // Already a plain list of labels.
        return array_values(array_filter($types, 'is_string'));
    }

    // -------------------------------------------------------------------------
    // Scheduler
    // -------------------------------------------------------------------------

    public function onSchedulerInitialized(Event $e): void
    {
        $scheduler = $e['scheduler'];
        $config    = $this->config();

        if (!empty($config['auto_clean'])) {
            $job = $scheduler->addFunction('Grav\Plugin\GrvhulkPlugin::taskCleanBlacklists', [], 'grvhulk-auto-clean');
            $job->backlink('plugins/grvhulk');
            $job->at('35 2 * * *');
        }

        if (!empty($config['auto_cache']) && !empty($config['sources']['abuseipdb_bulk']) && !empty($config['abuseipdb']['api_key'])) {
            $job = $scheduler->addFunction('Grav\Plugin\GrvhulkPlugin::taskUpdateAbuseipdbBulk', [], 'grvhulk-abuseipdb-cache');
            $job->backlink('plugins/grvhulk');
            $job->at('45 2 * * *');
        }

        if (!empty($config['sources']['dark_visitors']) && !empty($config['dark_visitors']['api_key'])) {
            $job = $scheduler->addFunction('Grav\Plugin\GrvhulkPlugin::taskUpdateDarkVisitors', [], 'grvhulk-dark-visitors');
            $job->backlink('plugins/grvhulk');
            $job->at('0 3 * * *');
        }

        if (!empty($config['enable_reporting']) && !empty($config['abuseipdb']['api_key'])) {
            $job = $scheduler->addFunction('Grav\Plugin\GrvhulkPlugin::taskFlushReports', [], 'grvhulk-flush-reports');
            $job->backlink('plugins/grvhulk');
            $job->at('*/10 * * * *');
        }
    }

    // -------------------------------------------------------------------------
    // Admin menu
    // -------------------------------------------------------------------------

    public function onAdminMenu(): void
    {
        $this->grav['twig']->plugins_hooked_nav['GRVHulk'] = [
            'hint'      => 'Hulk IP Security Manager',
            'route'     => 'hulk',
            'icon'      => 'fa-shield',
            'authorize' => 'admin.users',
        ];
    }

    public function onAdminTwigTemplatePaths(Event $event): void
    {
        if (in_array($this->grav['uri']->route(), ['/admin/hulk'], true)) {
            $event['paths'] = array_merge($event['paths'], [__DIR__ . '/admin/templates']);
        }
    }

    // -------------------------------------------------------------------------
    // Static scheduler task methods (called in separate PHP process by Grav scheduler)
    // -------------------------------------------------------------------------

    public static function taskCleanBlacklists(): void
    {
        $grav    = Grav::instance();
        $config  = $grav['config']->get('plugins.grvhulk');
        $dataDir = $grav['locator']->findResource('user://data', true) . '/grvhulk';
        $db      = HulkDatabase::getInstance($dataDir);
        $limit   = (int)($config['auto_clean_limit'] ?? 10000);

        $localTtl = (int)($config['local_ttl'] ?? 86400);
        $expired  = HulkDatabase::pruneExpiredLocal($db, $localTtl);
        HulkDatabase::trimLocal($db, $limit);
        HulkDatabase::pruneExpiredCache($db);
        $db->exec('VACUUM');

        echo "Hulk: pruned {$expired} expired local entries (ttl:{$localTtl}s), trimmed to {$limit}, vacuumed DB.\n";
    }

    public static function taskUpdateAbuseipdbBulk(): void
    {
        $grav   = Grav::instance();
        $config = $grav['config']->get('plugins.grvhulk');

        if (empty($config['abuseipdb']['api_key'])) {
            echo "Hulk: AbuseIPDB api_key not configured, skipping bulk update.\n";
            return;
        }

        $dataDir = $grav['locator']->findResource('user://data', true) . '/grvhulk';
        $db      = HulkDatabase::getInstance($dataDir);
        $client  = new AbuseIpDbClient($config['abuseipdb']);
        $limit   = (int)($config['abuseipdb']['bulk_limit'] ?? 10000);

        try {
            $ips   = $client->fetchBulkBlacklist($limit);
            $count = HulkDatabase::replaceBulkList($db, $ips);
            HulkDatabase::setMeta($db, 'abuseipdb_bulk_updated', (string)time());
            HulkDatabase::setMeta($db, 'abuseipdb_bulk_count', (string)$count);
            echo "Hulk: AbuseIPDB bulk updated ({$count} IPs).\n";
        } catch (\Throwable $e) {
            echo "Hulk: AbuseIPDB bulk update failed: " . $e->getMessage() . "\n";
        }
    }

    public static function taskUpdateDarkVisitors(): void
    {
        $grav   = Grav::instance();
        $config = $grav['config']->get('plugins.grvhulk');

        if (empty($config['dark_visitors']['api_key'])) {
            echo "Hulk: Known Agents api_key not configured, skipping update.\n";
            return;
        }

        $dataDir = $grav['locator']->findResource('user://data', true) . '/grvhulk';
        $db      = HulkDatabase::getInstance($dataDir);
        $client  = new DarkVisitorsClient($config['dark_visitors']['api_key']);
        $types   = self::normalizeAgentTypes($config['dark_visitors']['agent_types'] ?? []);

        try {
            $agents = $client->fetchAgents($types);
            HulkDatabase::replaceDarkVisitorsAgents($db, $agents);
            HulkDatabase::setMeta($db, 'dark_visitors_updated', (string)time());
            $count = count($agents);
            echo "Hulk: Known Agents list updated ({$count} user-agents).\n";
        } catch (\Throwable $e) {
            echo "Hulk: Known Agents update failed: " . $e->getMessage() . "\n";
        }
    }

    /**
     * Flush queued AbuseIPDB reports. Reporting is deferred off the request hot
     * path (a synchronous external POST per matched request would expose the
     * site to PHP-FPM worker exhaustion), so this scheduler job sends them.
     */
    public static function taskFlushReports(): void
    {
        $grav   = Grav::instance();
        $config = $grav['config']->get('plugins.grvhulk');

        if (empty($config['abuseipdb']['api_key'])) {
            echo "Hulk: AbuseIPDB api_key not configured, skipping report flush.\n";
            return;
        }

        $dataDir = $grav['locator']->findResource('user://data', true) . '/grvhulk';
        $db      = HulkDatabase::getInstance($dataDir);
        $client  = new AbuseIpDbClient($config['abuseipdb']);

        $sent = 0;
        $failed = 0;
        foreach (HulkDatabase::getPendingReports($db, 200) as $report) {
            if ($client->reportIp($report['ip'], $report['path'])) {
                HulkDatabase::deleteReport($db, (int)$report['id']);
                $sent++;
            } else {
                // Keep the row for a later retry (dropped after maxAttempts).
                HulkDatabase::failReport($db, (int)$report['id']);
                $failed++;
            }
        }

        echo "Hulk: flushed {$sent} queued AbuseIPDB report(s), {$failed} deferred.\n";
    }
}
