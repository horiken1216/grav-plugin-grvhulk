<?php
namespace Grav\Plugin\Grvhulk\Tests;

use Grav\Plugin\Grvhulk\IpDetector;
use PHPUnit\Framework\TestCase;

class IpDetectorTest extends TestCase
{
    private array $serverBackup = [];

    protected function setUp(): void
    {
        $this->serverBackup = $_SERVER;
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->serverBackup;
    }

    // ── isValidPublicIp ──────────────────────────────────────────────────────

    public function testPublicIpIsValid(): void
    {
        $this->assertTrue(IpDetector::isValidPublicIp('8.8.8.8'));
        $this->assertTrue(IpDetector::isValidPublicIp('203.0.113.1'));
        // A genuinely-routable IPv6 (Cloudflare DNS). 2001:db8::/32 is the
        // reserved documentation range and is correctly treated as non-public.
        $this->assertTrue(IpDetector::isValidPublicIp('2606:4700:4700::1111'));
    }

    public function testPrivateIpIsNotValid(): void
    {
        $this->assertFalse(IpDetector::isValidPublicIp('192.168.1.1'));
        $this->assertFalse(IpDetector::isValidPublicIp('10.0.0.1'));
        $this->assertFalse(IpDetector::isValidPublicIp('172.16.0.1'));
        $this->assertFalse(IpDetector::isValidPublicIp('::1'));
    }

    public function testReservedIpIsNotValid(): void
    {
        $this->assertFalse(IpDetector::isValidPublicIp('127.0.0.1'));
        $this->assertFalse(IpDetector::isValidPublicIp('0.0.0.0'));
    }

    // ── isWhitelisted — exact match ──────────────────────────────────────────

    public function testExactIpMatch(): void
    {
        $this->assertTrue(IpDetector::isWhitelisted('1.2.3.4', ['1.2.3.4']));
    }

    public function testExactIpNotInList(): void
    {
        $this->assertFalse(IpDetector::isWhitelisted('1.2.3.5', ['1.2.3.4']));
    }

    public function testEmptyWhitelistReturnsFalse(): void
    {
        $this->assertFalse(IpDetector::isWhitelisted('1.2.3.4', []));
    }

    // ── isWhitelisted — CIDR IPv4 ────────────────────────────────────────────

    public function testIpInsideCidr(): void
    {
        $this->assertTrue(IpDetector::isWhitelisted('192.168.1.5', ['192.168.1.0/24']));
        $this->assertTrue(IpDetector::isWhitelisted('10.0.0.1', ['10.0.0.0/8']));
        $this->assertTrue(IpDetector::isWhitelisted('10.255.255.255', ['10.0.0.0/8']));
    }

    public function testIpOutsideCidr(): void
    {
        $this->assertFalse(IpDetector::isWhitelisted('192.168.2.1', ['192.168.1.0/24']));
        $this->assertFalse(IpDetector::isWhitelisted('11.0.0.1', ['10.0.0.0/8']));
    }

    public function testHostBitsCidr(): void
    {
        $this->assertTrue(IpDetector::isWhitelisted('203.0.113.45', ['203.0.113.45/32']));
        $this->assertFalse(IpDetector::isWhitelisted('203.0.113.46', ['203.0.113.45/32']));
    }

    public function testCidrSlashZeroMatchesAll(): void
    {
        $this->assertTrue(IpDetector::isWhitelisted('1.2.3.4', ['0.0.0.0/0']));
    }

    // ── isWhitelisted — CIDR IPv6 ────────────────────────────────────────────

    public function testIpv6InsideCidr(): void
    {
        $this->assertTrue(IpDetector::isWhitelisted('2001:db8::1', ['2001:db8::/32']));
        $this->assertTrue(IpDetector::isWhitelisted('2001:db8:ffff::1', ['2001:db8::/32']));
    }

    public function testIpv6OutsideCidr(): void
    {
        $this->assertFalse(IpDetector::isWhitelisted('2001:db9::1', ['2001:db8::/32']));
    }

    public function testIpv6ExactMatch(): void
    {
        $this->assertTrue(IpDetector::isWhitelisted('::1', ['::1']));
    }

    // ── isWhitelisted — mixed / edge cases ───────────────────────────────────

    public function testIpv4NotMatchedByIpv6Cidr(): void
    {
        $this->assertFalse(IpDetector::isWhitelisted('1.2.3.4', ['::1/128']));
    }

    public function testWhitelistWithMixedEntries(): void
    {
        $whitelist = ['127.0.0.1', '::1', '10.0.0.0/8'];
        $this->assertTrue(IpDetector::isWhitelisted('127.0.0.1', $whitelist));
        $this->assertTrue(IpDetector::isWhitelisted('::1', $whitelist));
        $this->assertTrue(IpDetector::isWhitelisted('10.50.0.1', $whitelist));
        $this->assertFalse(IpDetector::isWhitelisted('8.8.8.8', $whitelist));
    }

    // ── getClientIp ──────────────────────────────────────────────────────────

    public function testGetClientIpFromRemoteAddr(): void
    {
        unset($_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP'],
              $_SERVER['HTTP_CLIENT_IP'], $_SERVER['HTTP_X_FORWARDED_FOR']);
        $_SERVER['REMOTE_ADDR'] = '5.6.7.8';
        $this->assertSame('5.6.7.8', IpDetector::getClientIp());
    }

    public function testForwardingHeadersIgnoredWithoutTrustedProxy(): void
    {
        // Spoof protection: an untrusted peer cannot dictate the client IP.
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '1.1.1.1';
        $_SERVER['HTTP_X_FORWARDED_FOR']  = '2.2.2.2';
        $_SERVER['REMOTE_ADDR']           = '3.3.3.3';
        $this->assertSame('3.3.3.3', IpDetector::getClientIp());
        $this->assertSame('3.3.3.3', IpDetector::getClientIp(['203.0.113.0/24']));
    }

    public function testCloudflareHeaderHonoredBehindTrustedProxy(): void
    {
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '1.1.1.1';
        $_SERVER['HTTP_X_FORWARDED_FOR']  = '2.2.2.2';
        $_SERVER['REMOTE_ADDR']           = '3.3.3.3';
        $this->assertSame('1.1.1.1', IpDetector::getClientIp(['3.3.3.3']));
    }

    public function testXForwardedForSkipsTrustedProxyHops(): void
    {
        unset($_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_CLIENT_IP']);
        // Chain: real client 9.9.9.9 → proxy 10.0.0.5 → our edge (REMOTE_ADDR).
        // Walking right-to-left skips the trusted proxy and returns the client.
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '9.9.9.9, 10.0.0.5';
        $_SERVER['REMOTE_ADDR']          = '10.0.0.1';
        $this->assertSame('9.9.9.9', IpDetector::getClientIp(['10.0.0.0/8']));
    }

    public function testXForwardedForSpoofResistsInjectedLeftmost(): void
    {
        unset($_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_CLIENT_IP']);
        // Attacker prepends a fake hop; the rightmost non-proxy entry wins.
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 9.9.9.9, 10.0.0.5';
        $_SERVER['REMOTE_ADDR']          = '10.0.0.1';
        $this->assertSame('9.9.9.9', IpDetector::getClientIp(['10.0.0.0/8']));
    }
}
