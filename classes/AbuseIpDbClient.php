<?php
namespace Grav\Plugin\Grvhulk;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Generator;

/**
 * AbuseIPDB v2 API client.
 * Fail-open: all exceptions return 'clean' decision.
 */
class AbuseIpDbClient
{
    private Client $http;
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->http = new Client([
            'base_uri'        => 'https://api.abuseipdb.com',
            'timeout'         => 5.0,
            'connect_timeout' => 3.0,
            'headers'         => [
                'Key'    => $config['api_key'] ?? '',
                'Accept' => 'application/json',
            ],
        ]);
    }

    /**
     * Fetch bulk IP blacklist as a streaming generator.
     * Yields string IP addresses one by one to avoid loading all into memory.
     * Uses Accept: text/plain (newline-delimited IPs).
     */
    public function fetchBulkBlacklist(int $limit = 10000): Generator
    {
        if (empty($this->config['api_key'])) {
            return;
        }

        try {
            $response = $this->http->get('/api/v2/blacklist', [
                'query'   => ['limit' => $limit],
                'headers' => ['Accept' => 'text/plain'],
                'stream'  => true,
            ]);

            $body   = $response->getBody();
            $buffer = '';
            // Guard against a malformed/hostile response with no newlines, which
            // would otherwise grow $buffer until memory is exhausted. No valid
            // line (an IP) approaches this size.
            $maxLineBytes = 64 * 1024;

            while (!$body->eof()) {
                $buffer .= $body->read(8192);
                while (($pos = strpos($buffer, "\n")) !== false) {
                    $line = trim(substr($buffer, 0, $pos));
                    $buffer = substr($buffer, $pos + 1);
                    if ($line !== '' && $line[0] !== '#' && filter_var($line, FILTER_VALIDATE_IP)) {
                        yield $line;
                    }
                }
                if (strlen($buffer) > $maxLineBytes) {
                    // Pathological response — abort rather than exhaust memory.
                    return;
                }
            }
            // Last line without newline
            $line = trim($buffer);
            if ($line !== '' && $line[0] !== '#' && filter_var($line, FILTER_VALIDATE_IP)) {
                yield $line;
            }
        } catch (GuzzleException $e) {
            // Yield nothing on error
        }
    }

    /**
     * Report an IP to AbuseIPDB (category 21 = Web App Attack).
     */
    public function reportIp(string $ip, string $path, int $category = 21): bool
    {
        if (empty($this->config['api_key'])) {
            return false;
        }

        try {
            $response = $this->http->post('/api/v2/report', [
                'form_params' => [
                    'ip'         => $ip,
                    'categories' => (string)$category,
                    'comment'    => 'Blocked by GRVHulk. Path: ' . substr($path, 0, 500),
                ],
            ]);
            return $response->getStatusCode() === 200;
        } catch (GuzzleException $e) {
            return false;
        }
    }
}
