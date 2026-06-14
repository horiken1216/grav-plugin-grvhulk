<?php
namespace Grav\Plugin\Grvhulk\Tests;

use Grav\Plugin\Grvhulk\HulkDatabase;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SQLite3;

class HulkDatabaseTest extends TestCase
{
    private SQLite3 $db;
    private string $tempDir;

    protected function setUp(): void
    {
        // Reset the singleton so each test gets a fresh database
        $ref = new ReflectionClass(HulkDatabase::class);
        $prop = $ref->getProperty('instance');
        $prop->setAccessible(true);
        $prop->setValue(null, null);

        $this->tempDir = sys_get_temp_dir() . '/grvhulk_test_' . uniqid();
        mkdir($this->tempDir, 0777, true);
        $this->db = HulkDatabase::getInstance($this->tempDir);
    }

    protected function tearDown(): void
    {
        // Reset singleton so we don't bleed state between tests
        $ref = new ReflectionClass(HulkDatabase::class);
        $prop = $ref->getProperty('instance');
        $prop->setAccessible(true);
        $prop->setValue(null, null);

        $this->db->close();

        // Remove temp files
        $dbFile = $this->tempDir . '/grvhulk.sqlite';
        foreach (glob($dbFile . '*') as $f) {
            @unlink($f);
        }
        @rmdir($this->tempDir);
    }

    // ── Local blacklist ──────────────────────────────────────────────────────

    public function testAddAndCheckIpInLocal(): void
    {
        $this->assertFalse(HulkDatabase::isIpInLocal($this->db, '1.2.3.4'));
        HulkDatabase::addIpToLocal($this->db, '1.2.3.4', 'test');
        $this->assertTrue(HulkDatabase::isIpInLocal($this->db, '1.2.3.4'));
    }

    public function testLocalTtlExpiry(): void
    {
        // Manually insert an entry with a past timestamp to simulate expiry
        $this->db->exec("INSERT INTO local (ip, reason, added_at) VALUES ('9.9.9.9', 'old', " . (time() - 7200) . ")");
        // TTL=3600 (1h): entry is 2h old → expired
        $this->assertFalse(HulkDatabase::isIpInLocal($this->db, '9.9.9.9', 3600));
        // TTL=0 (permanent): same entry is still found
        $this->assertTrue(HulkDatabase::isIpInLocal($this->db, '9.9.9.9', 0));
    }

    public function testPruneExpiredLocal(): void
    {
        $this->db->exec("INSERT INTO local (ip, reason, added_at) VALUES ('1.1.1.1', 'old', " . (time() - 7200) . ")");
        HulkDatabase::addIpToLocal($this->db, '2.2.2.2', 'fresh');
        // Prune with TTL=3600: only the 2h-old entry should be removed
        $removed = HulkDatabase::pruneExpiredLocal($this->db, 3600);
        $this->assertSame(1, $removed);
        $this->assertFalse(HulkDatabase::isIpInLocal($this->db, '1.1.1.1', 0));
        $this->assertTrue(HulkDatabase::isIpInLocal($this->db, '2.2.2.2', 0));
    }

    public function testRemoveIpFromLocal(): void
    {
        HulkDatabase::addIpToLocal($this->db, '1.2.3.4');
        HulkDatabase::removeIpFromLocal($this->db, '1.2.3.4');
        $this->assertFalse(HulkDatabase::isIpInLocal($this->db, '1.2.3.4'));
    }

    public function testAddDuplicateIpIsIgnored(): void
    {
        HulkDatabase::addIpToLocal($this->db, '1.2.3.4', 'first');
        HulkDatabase::addIpToLocal($this->db, '1.2.3.4', 'second');
        $this->assertSame(1, HulkDatabase::getLocalCount($this->db));
    }

    public function testGetLocalCount(): void
    {
        $this->assertSame(0, HulkDatabase::getLocalCount($this->db));
        HulkDatabase::addIpToLocal($this->db, '1.1.1.1');
        HulkDatabase::addIpToLocal($this->db, '2.2.2.2');
        $this->assertSame(2, HulkDatabase::getLocalCount($this->db));
    }

    public function testGetLastNLocal(): void
    {
        HulkDatabase::addIpToLocal($this->db, '1.1.1.1', 'first');
        HulkDatabase::addIpToLocal($this->db, '2.2.2.2', 'second');
        $rows = HulkDatabase::getLastNLocal($this->db, 25);
        $this->assertCount(2, $rows);
        // Most recent row first (ORDER BY rowid DESC)
        $this->assertSame('2.2.2.2', $rows[0]['ip']);
        $this->assertSame('second', $rows[0]['reason']);
    }

    public function testSearchLocalFound(): void
    {
        HulkDatabase::addIpToLocal($this->db, '5.6.7.8', 'scan');
        $entry = HulkDatabase::searchLocal($this->db, '5.6.7.8');
        $this->assertNotNull($entry);
        $this->assertSame('5.6.7.8', $entry['ip']);
        $this->assertSame('scan', $entry['reason']);
    }

    public function testSearchLocalNotFound(): void
    {
        $this->assertNull(HulkDatabase::searchLocal($this->db, '9.9.9.9'));
    }

    // ── IP cache ─────────────────────────────────────────────────────────────

    public function testSetAndGetCachedDecision(): void
    {
        HulkDatabase::setCachedDecision($this->db, '1.2.3.4', 'crowdsec_cti', 'block', 90, 300);
        $cached = HulkDatabase::getCachedDecision($this->db, '1.2.3.4', 'crowdsec_cti');
        $this->assertNotNull($cached);
        $this->assertSame('block', $cached['decision']);
        $this->assertSame(90, (int)$cached['score']);
    }

    public function testCachedDecisionReturnsNullWhenMissing(): void
    {
        $this->assertNull(HulkDatabase::getCachedDecision($this->db, '99.99.99.99', 'crowdsec_cti'));
    }

    public function testExpiredCacheReturnsNull(): void
    {
        // TTL = -1 means already expired
        HulkDatabase::setCachedDecision($this->db, '1.2.3.4', 'crowdsec_cti', 'block', 5, -1);
        $this->assertNull(HulkDatabase::getCachedDecision($this->db, '1.2.3.4', 'crowdsec_cti'));
    }

    public function testCacheSeparatedBySource(): void
    {
        HulkDatabase::setCachedDecision($this->db, '1.2.3.4', 'crowdsec_cti', 'block', 80, 300);
        HulkDatabase::setCachedDecision($this->db, '1.2.3.4', 'crowdsec_lapi', 'clean', 0, 300);

        $a = HulkDatabase::getCachedDecision($this->db, '1.2.3.4', 'crowdsec_cti');
        $c = HulkDatabase::getCachedDecision($this->db, '1.2.3.4', 'crowdsec_lapi');

        $this->assertSame('block', $a['decision']);
        $this->assertSame('clean', $c['decision']);
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    public function testSetAndGetMeta(): void
    {
        HulkDatabase::setMeta($this->db, 'test_key', 'hello');
        $this->assertSame('hello', HulkDatabase::getMeta($this->db, 'test_key'));
    }

    public function testGetMetaReturnsNullWhenMissing(): void
    {
        $this->assertNull(HulkDatabase::getMeta($this->db, 'nonexistent'));
    }

    public function testSetMetaOverwritesExistingValue(): void
    {
        HulkDatabase::setMeta($this->db, 'k', 'v1');
        HulkDatabase::setMeta($this->db, 'k', 'v2');
        $this->assertSame('v2', HulkDatabase::getMeta($this->db, 'k'));
    }

    // ── Dark Visitors agents ─────────────────────────────────────────────────

    public function testDarkVisitorsAgentBlocked(): void
    {
        HulkDatabase::replaceDarkVisitorsAgents($this->db, ['GPTBot', 'ClaudeBot']);
        $this->assertTrue(HulkDatabase::isDarkVisitorsAgentBlocked($this->db, 'Mozilla/5.0 GPTBot/1.0'));
    }

    public function testDarkVisitorsAgentNotBlocked(): void
    {
        HulkDatabase::replaceDarkVisitorsAgents($this->db, ['GPTBot']);
        $this->assertFalse(HulkDatabase::isDarkVisitorsAgentBlocked($this->db, 'Mozilla/5.0 (compatible; Googlebot)'));
    }

    public function testDarkVisitorsAgentCaseInsensitive(): void
    {
        HulkDatabase::replaceDarkVisitorsAgents($this->db, ['GPTBot']);
        $this->assertTrue(HulkDatabase::isDarkVisitorsAgentBlocked($this->db, 'Mozilla/5.0 gptbot/1.0'));
    }

    public function testDarkVisitorsEmptyUaReturnsFalse(): void
    {
        HulkDatabase::replaceDarkVisitorsAgents($this->db, ['GPTBot']);
        $this->assertFalse(HulkDatabase::isDarkVisitorsAgentBlocked($this->db, ''));
    }

    public function testDarkVisitorsGetCount(): void
    {
        $this->assertSame(0, HulkDatabase::getDarkVisitorsCount($this->db));
        HulkDatabase::replaceDarkVisitorsAgents($this->db, ['GPTBot', 'ClaudeBot', 'PerplexityBot']);
        $this->assertSame(3, HulkDatabase::getDarkVisitorsCount($this->db));
    }

    public function testReplaceAgentsClearsOldEntries(): void
    {
        HulkDatabase::replaceDarkVisitorsAgents($this->db, ['OldBot']);
        HulkDatabase::replaceDarkVisitorsAgents($this->db, ['NewBot']);
        $this->assertFalse(HulkDatabase::isDarkVisitorsAgentBlocked($this->db, 'OldBot'));
        $this->assertTrue(HulkDatabase::isDarkVisitorsAgentBlocked($this->db, 'NewBot'));
    }

    public function testDarkVisitorsBackslashEscaping(): void
    {
        // A stored agent containing a literal backslash must still match the same
        // literal in an incoming UA. The escape character has to be escaped first,
        // otherwise '\B' would be consumed as an escape and the match would fail.
        HulkDatabase::replaceDarkVisitorsAgents($this->db, ['Bad\\Bot']);
        $this->assertTrue(HulkDatabase::isDarkVisitorsAgentBlocked($this->db, 'Mozilla Bad\\Bot/1.0'));
        $this->assertFalse(HulkDatabase::isDarkVisitorsAgentBlocked($this->db, 'Mozilla BadBot/1.0'));
    }

    // ── Manual vs auto local entries ─────────────────────────────────────────

    public function testManualEntryNotExpiredByTtl(): void
    {
        // Manual entry with an old timestamp must still be enforced and not pruned.
        $this->db->exec("INSERT INTO local (ip, reason, is_manual, added_at) VALUES ('7.7.7.7', 'manual', 1, " . (time() - 7200) . ")");
        $this->assertTrue(HulkDatabase::isIpInLocal($this->db, '7.7.7.7', 3600));
        $removed = HulkDatabase::pruneExpiredLocal($this->db, 3600);
        $this->assertSame(0, $removed);
        $this->assertTrue(HulkDatabase::isIpInLocal($this->db, '7.7.7.7', 0));
    }

    public function testManualEntryNotTrimmed(): void
    {
        $this->db->exec("INSERT INTO local (ip, reason, is_manual, added_at) VALUES ('9.9.9.9', 'manual', 1, " . (time() - 100) . ")");
        HulkDatabase::addIpToLocal($this->db, '1.1.1.1', 'auto');
        HulkDatabase::addIpToLocal($this->db, '2.2.2.2', 'auto');
        // Trim auto entries down to 1; the manual entry is always kept.
        HulkDatabase::trimLocal($this->db, 1);
        $this->assertTrue(HulkDatabase::isIpInLocal($this->db, '9.9.9.9'));
        $this->assertSame(2, HulkDatabase::getLocalCount($this->db)); // manual + 1 auto
    }

    public function testManualAddViaAddIpToLocal(): void
    {
        HulkDatabase::addIpToLocal($this->db, '3.3.3.3', 'manual', true);
        $row = HulkDatabase::searchLocal($this->db, '3.3.3.3');
        $this->assertSame(1, (int)$row['is_manual']);
    }

    public function testManualAddPromotesExistingAutoEntry(): void
    {
        // An auto entry that is later added manually must be promoted, not ignored.
        HulkDatabase::addIpToLocal($this->db, '4.4.4.4', 'URI filter', false);
        HulkDatabase::addIpToLocal($this->db, '4.4.4.4', 'admin add', true);
        $row = HulkDatabase::searchLocal($this->db, '4.4.4.4');
        $this->assertSame(1, (int)$row['is_manual']);
        $this->assertSame('admin add', $row['reason']);
        $this->assertSame(1, HulkDatabase::getLocalCount($this->db));
    }

    public function testAutoAddDoesNotDemoteManualEntry(): void
    {
        HulkDatabase::addIpToLocal($this->db, '5.5.5.5', 'admin add', true);
        HulkDatabase::addIpToLocal($this->db, '5.5.5.5', 'URI filter', false);
        $row = HulkDatabase::searchLocal($this->db, '5.5.5.5');
        $this->assertSame(1, (int)$row['is_manual']);
        $this->assertSame('admin add', $row['reason']);
    }

    // ── Report queue ─────────────────────────────────────────────────────────

    public function testReportQueueRoundTrip(): void
    {
        $this->assertSame([], HulkDatabase::getPendingReports($this->db));
        HulkDatabase::enqueueReport($this->db, '1.2.3.4', '/wp-login.php');
        $pending = HulkDatabase::getPendingReports($this->db, 10);
        $this->assertCount(1, $pending);
        $this->assertSame('1.2.3.4', $pending[0]['ip']);
        $this->assertSame('/wp-login.php', $pending[0]['path']);
        HulkDatabase::deleteReport($this->db, (int)$pending[0]['id']);
        $this->assertSame([], HulkDatabase::getPendingReports($this->db));
    }

    public function testFailedReportRetriedThenDropped(): void
    {
        HulkDatabase::enqueueReport($this->db, '1.2.3.4', '/x');
        $id = (int)HulkDatabase::getPendingReports($this->db)[0]['id'];

        // Below the cap it is retained for retry; at the cap it is dropped.
        HulkDatabase::failReport($this->db, $id, 3); // attempts 1
        $this->assertCount(1, HulkDatabase::getPendingReports($this->db));
        HulkDatabase::failReport($this->db, $id, 3); // attempts 2
        $this->assertCount(1, HulkDatabase::getPendingReports($this->db));
        HulkDatabase::failReport($this->db, $id, 3); // attempts 3 -> dropped
        $this->assertSame([], HulkDatabase::getPendingReports($this->db));
    }
}
