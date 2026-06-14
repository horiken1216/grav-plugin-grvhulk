<?php
namespace Grav\Plugin\Grvhulk;

/**
 * Client IP detection and whitelist evaluation.
 * All methods are static.
 */
class IpDetector
{
    /**
     * Detect the real client IP address.
     *
     * Client-supplied forwarding headers (CF-Connecting-IP, X-Real-IP,
     * X-Forwarded-For) are trivially spoofable, so they are honored ONLY when
     * the connecting peer (REMOTE_ADDR) is in the admin-configured
     * $trustedProxies list (IPs or CIDRs). Without a trusted-proxy match the
     * raw REMOTE_ADDR is returned — preventing attackers from evading blocks or
     * blacklisting third parties by forging these headers.
     *
     * @param string[] $trustedProxies IPs/CIDRs of reverse proxies/CDNs allowed
     *                                  to set forwarding headers. Empty = trust none.
     */
    public static function getClientIp(array $trustedProxies = []): string
    {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // Only consult forwarding headers when the direct peer is a trusted proxy.
        if ($trustedProxies === [] || !self::isWhitelisted($remoteAddr, $trustedProxies)) {
            return $remoteAddr;
        }

        // Cloudflare (single value, set by the trusted edge)
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        // nginx X-Real-IP (single value, set by the trusted proxy)
        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $ip = trim($_SERVER['HTTP_X_REAL_IP']);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        // X-Forwarded-For: the rightmost entry is added by our trusted proxy and
        // each hop prepends. Walk right-to-left, skipping known trusted-proxy
        // hops, and return the first address that isn't one of our proxies — the
        // real client. Anything to the left of that may be attacker-injected.
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
            for ($i = count($parts) - 1; $i >= 0; $i--) {
                $candidate = $parts[$i];
                if (!filter_var($candidate, FILTER_VALIDATE_IP)) {
                    continue;
                }
                if (self::isWhitelisted($candidate, $trustedProxies)) {
                    continue; // skip a known proxy hop
                }
                return $candidate;
            }
        }

        return $remoteAddr;
    }

    /**
     * Returns true if $ip is a routable public IP (not private/reserved).
     * Private ranges should never be blacklisted or checked against APIs.
     */
    public static function isValidPublicIp(string $ip): bool
    {
        return (bool)filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    /**
     * Check if $ip matches any entry in the whitelist.
     * Entries can be exact IPs or CIDR notation (e.g. '192.168.0.0/24', '2001:db8::/32').
     */
    public static function isWhitelisted(string $ip, array $whitelist): bool
    {
        foreach ($whitelist as $entry) {
            $entry = trim((string)$entry);
            if ($entry === '') {
                continue;
            }

            if (str_contains($entry, '/')) {
                if (self::ipInCidr($ip, $entry)) {
                    return true;
                }
            } elseif (strcasecmp($ip, $entry) === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Test whether $ip falls within the CIDR range $cidr.
     * Supports both IPv4 and IPv6 using packed-byte comparison, which is
     * platform-independent (no 32-bit integer overflow concerns).
     */
    private static function ipInCidr(string $ip, string $cidr): bool
    {
        [$net, $bitsStr] = array_pad(explode('/', $cidr, 2), 2, null);
        if ($bitsStr === null || $bitsStr === '') {
            return false;
        }
        $bits = (int)$bitsStr;

        $ipBin  = @inet_pton($ip);
        $netBin = @inet_pton($net);
        if ($ipBin === false || $netBin === false) {
            return false;
        }
        // Reject mixing IPv4 and IPv6 (different byte lengths)
        if (strlen($ipBin) !== strlen($netBin)) {
            return false;
        }

        $maxBits = strlen($ipBin) * 8;
        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $fullBytes = intdiv($bits, 8);
        $remainder = $bits % 8;

        if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($netBin, 0, $fullBytes)) {
            return false;
        }
        if ($remainder > 0) {
            $mask = 0xFF & (0xFF << (8 - $remainder));
            if ((ord($ipBin[$fullBytes]) & $mask) !== (ord($netBin[$fullBytes]) & $mask)) {
                return false;
            }
        }
        return true;
    }
}
