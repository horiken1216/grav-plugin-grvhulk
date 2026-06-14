<?php
namespace Grav\Plugin\Grvhulk;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

/**
 * Known Agents (formerly Dark Visitors) API client.
 * Fetches a list of AI crawler user-agent strings via the robots-txts endpoint.
 * API: https://api.knownagents.com
 */
class DarkVisitorsClient
{
    private string $apiKey;
    private Client $http;

    public function __construct(string $apiKey)
    {
        $this->apiKey = $apiKey;
        $this->http = new Client([
            'base_uri'        => 'https://api.knownagents.com',
            'timeout'         => 10.0,
            'connect_timeout' => 5.0,
        ]);
    }

    /**
     * Fetch list of AI agent user-agent strings for the given agent types.
     *
     * The API returns robots.txt-formatted text; we parse out "User-agent: X" lines.
     * Available types: 'AI Assistant', 'AI Data Scraper', 'AI Search Crawler', 'Undocumented AI Agent'
     *
     * @param string[] $agentTypes
     * @return string[]  List of user-agent strings to block
     */
    public function fetchAgents(array $agentTypes): array
    {
        if (empty($this->apiKey) || empty($agentTypes)) {
            return [];
        }

        try {
            $response = $this->http->post('/robots-txts', [
                'headers' => [
                    'Authorization' => 'Bearer ' . $this->apiKey,
                    'Content-Type'  => 'application/json',
                ],
                'json' => [
                    'agent_types' => $agentTypes,
                    'disallow'    => '/',
                ],
            ]);

            $text   = (string)$response->getBody();
            $agents = [];

            foreach (explode("\n", $text) as $line) {
                $line = trim($line);
                if (stripos($line, 'User-agent:') === 0) {
                    $ua = trim(substr($line, strlen('User-agent:')));
                    if ($ua !== '' && $ua !== '*') {
                        $agents[] = $ua;
                    }
                }
            }

            return array_unique($agents);
        } catch (GuzzleException $e) {
            return [];
        }
    }
}
