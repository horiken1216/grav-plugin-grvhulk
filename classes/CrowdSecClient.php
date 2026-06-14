<?php
namespace Grav\Plugin\Grvhulk;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use SQLite3;

/**
 * CrowdSec IP reputation client.
 * Supports two modes:
 *   - cti:  cloud-based CTI API (cti.api.crowdsec.net)
 *   - lapi: self-hosted Local API
 *
 * Fail-open: all exceptions return 'clean' decision.
 * CTI 429 (quota exceeded): sets a quota-lock in DB metadata until next UTC midnight.
 */
class CrowdSecClient
{
    private array $config;
    private SQLite3 $db;
    private ?Client $ctiClient = null;
    private ?Client $lapiClient = null;

    public function __construct(array $config, SQLite3 $db)
    {
        $this->config = $config;
        $this->db = $db;
    }

    /**
     * Check $ip against CrowdSec.
     * Returns ['decision' => 'block'|'clean', 'score' => int, 'reason' => string,
     *          'cacheable' => bool]. 'cacheable' is false for fail-open results
     * (quota lock, 429, network/API errors) so the caller does not cache a
     * non-authoritative "clean" for the full TTL.
     */
    public function checkIp(string $ip): array
    {
        return match ($this->config['mode'] ?? 'cti') {
            'lapi'  => $this->checkViaLapi($ip),
            default => $this->checkViaCti($ip),
        };
    }

    private function checkViaCti(string $ip): array
    {
        $apiKey = $this->config['cti_api_key'] ?? '';
        if (empty($apiKey)) {
            return self::clean();
        }

        // Check quota guard
        $quotaUntil = HulkDatabase::getMeta($this->db, 'crowdsec_cti_quota_reset');
        if ($quotaUntil !== null && (int)$quotaUntil > time()) {
            return self::clean('CTI quota exceeded');
        }

        try {
            $client   = $this->getCtiClient($apiKey);
            $response = $client->get('/v2/smoke/' . urlencode($ip));
            $body     = json_decode((string)$response->getBody(), true);

            $total     = (int)round((float)($body['scores']['overall']['total'] ?? 0));
            $threshold = (int)($this->config['cti_score_threshold'] ?? 3);

            $behaviors = array_column($body['behaviors'] ?? [], 'label');
            $reason    = implode(', ', array_slice($behaviors, 0, 3));

            return [
                'decision'  => $total >= $threshold ? 'block' : 'clean',
                'score'     => $total,
                'reason'    => $reason,
                'cacheable' => true,
            ];
        } catch (ClientException $e) {
            $code = $e->getResponse()->getStatusCode();
            if ($code === 404) {
                // IP not in CrowdSec intelligence = authoritative clean
                return self::clean('', true);
            }
            if ($code === 429) {
                // Quota exceeded: lock until next UTC midnight (CTI quota resets daily)
                try {
                    $midnight = (new \DateTime('tomorrow', new \DateTimeZone('UTC')))->getTimestamp();
                } catch (\Exception $ex) {
                    $midnight = time() + 86400;
                }
                HulkDatabase::setMeta($this->db, 'crowdsec_cti_quota_reset', (string)$midnight);
                return self::clean('CTI quota exceeded');
            }
            return self::clean();
        } catch (GuzzleException $e) {
            return self::clean();
        }
    }

    private function checkViaLapi(string $ip): array
    {
        $apiKey = $this->config['lapi_api_key'] ?? '';
        if (empty($apiKey)) {
            return self::clean();
        }

        try {
            $client   = $this->getLapiClient($apiKey);
            $response = $client->get('/v1/decisions', ['query' => ['ip' => $ip]]);
            $body     = json_decode((string)$response->getBody(), true);

            if (empty($body) || !is_array($body)) {
                // No active decisions = authoritative clean (the common case), so
                // this result is cacheable for the LAPI TTL.
                return self::clean('', true);
            }

            foreach ($body as $decision) {
                if (($decision['type'] ?? '') === 'ban') {
                    return [
                        'decision'  => 'block',
                        'score'     => 5,
                        'reason'    => $decision['scenario'] ?? 'CrowdSec ban',
                        'cacheable' => true,
                    ];
                }
            }

            return self::clean('', true);
        } catch (GuzzleException $e) {
            return self::clean();
        }
    }

    private function getCtiClient(string $apiKey): Client
    {
        if ($this->ctiClient === null) {
            $this->ctiClient = new Client([
                'base_uri'        => 'https://cti.api.crowdsec.net',
                'timeout'         => 5.0,
                'connect_timeout' => 3.0,
                'headers'         => ['x-api-key' => $apiKey],
            ]);
        }
        return $this->ctiClient;
    }

    private function getLapiClient(string $apiKey): Client
    {
        if ($this->lapiClient === null) {
            $this->lapiClient = new Client([
                'base_uri'        => rtrim($this->config['lapi_url'] ?? 'http://localhost:8080', '/'),
                'timeout'         => 3.0,
                'connect_timeout' => 2.0,
                'headers'         => ['Authorization' => 'ApiKey ' . $apiKey],
            ]);
        }
        return $this->lapiClient;
    }

    private static function clean(string $reason = '', bool $cacheable = false): array
    {
        return ['decision' => 'clean', 'score' => 0, 'reason' => $reason, 'cacheable' => $cacheable];
    }
}
