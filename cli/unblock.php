#!/usr/bin/env php
<?php
/**
 * GRVHulk — Emergency IP unblock tool
 *
 * Run from your Grav root when you have locked yourself out of the admin UI:
 *
 *   php user/plugins/grvhulk/cli/unblock.php 203.0.113.5
 *
 * Options:
 *   --list         Show the last 25 IPs in the local blacklist
 *   --whitelist    Also add the IP to hulk.yaml whitelist (persistent)
 *   --db=PATH      Override the path to grvhulk.sqlite
 */

// ── Argument parsing ──────────────────────────────────────────────────────────
// PHP's getopt() stops at the first non-option argument, so we parse manually.

$ip     = null;
$list   = false;
$addWl  = false;
$dbPath = null;

for ($i = 1; $i < $argc; $i++) {
    $arg = $argv[$i];
    if ($arg === '--list') {
        $list = true;
    } elseif ($arg === '--whitelist') {
        $addWl = true;
    } elseif (str_starts_with($arg, '--db=')) {
        $dbPath = substr($arg, 5);
    } elseif ($arg === '--db' && isset($argv[$i + 1])) {
        $dbPath = $argv[++$i];
    } elseif (!str_starts_with($arg, '-')) {
        $ip = $arg;
    }
}

if (!$list && !$ip) {
    fwrite(STDERR, <<<'USAGE'
GRVHulk emergency unblock

Usage:
  php cli/unblock.php <ip>             Remove IP from local blacklist
  php cli/unblock.php --list           Show last 25 blocked IPs
  php cli/unblock.php <ip> --whitelist Also add IP to grvhulk.yaml whitelist

Options:
  --db=PATH   Override path to grvhulk.sqlite

USAGE);
    exit(1);
}

// ── Locate the database ───────────────────────────────────────────────────────

if (!$dbPath) {
    // When running as: php user/plugins/grvhulk/cli/unblock.php
    // __DIR__ = [grav-root]/user/plugins/grvhulk/cli
    $candidate = __DIR__ . '/../../../data/grvhulk/grvhulk.sqlite';
    if (file_exists($candidate)) {
        $dbPath = realpath($candidate);
    }
}

if (!$dbPath || !file_exists($dbPath)) {
    fwrite(STDERR, "Error: cannot find grvhulk.sqlite.\n");
    fwrite(STDERR, "Run from Grav root, or pass --db=/path/to/grvhulk.sqlite\n");
    exit(1);
}

// ── Open DB ───────────────────────────────────────────────────────────────────

$db = new SQLite3($dbPath);
$db->enableExceptions(true);
$db->exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;');

// ── --list ────────────────────────────────────────────────────────────────────

if ($list) {
    $rows = $db->query(
        'SELECT ip, reason, datetime(added_at, \'unixepoch\', \'localtime\') AS added
         FROM local ORDER BY rowid DESC LIMIT 25'
    );
    $found = false;
    printf("%-18s %-30s %s\n", 'IP', 'Reason', 'Added');
    echo str_repeat('-', 70) . "\n";
    while ($row = $rows->fetchArray(SQLITE3_ASSOC)) {
        printf("%-18s %-30s %s\n", $row['ip'], $row['reason'] ?: '—', $row['added']);
        $found = true;
    }
    if (!$found) {
        echo "(Local blacklist is empty)\n";
    }
    $db->close();
    exit(0);
}

// ── Validate IP ───────────────────────────────────────────────────────────────

if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    fwrite(STDERR, "Error: \"$ip\" is not a valid IP address.\n");
    exit(1);
}

// ── Remove from local blacklist ───────────────────────────────────────────────

$stmt = $db->prepare('DELETE FROM local WHERE ip = :ip');
$stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
$stmt->execute();
$removed = $db->changes();
$db->close();

if ($removed > 0) {
    echo "✓ Removed $ip from local blacklist.\n";
} else {
    echo "Info: $ip was not in the local blacklist.\n";
}

// ── --whitelist: append to grvhulk.yaml ──────────────────────────────────────

if ($addWl) {
    // Write to the user override only: [grav-root]/user/config/plugins/grvhulk.yaml.
    // __DIR__ = [grav-root]/user/plugins/grvhulk/cli, so three '..' reach `user`.
    // Never touch the plugin's bundled default (it would be lost on update and
    // shipped config should stay pristine).
    $yamlPath = __DIR__ . '/../../../config/plugins/grvhulk.yaml';

    if (!file_exists($yamlPath)) {
        // No user override yet — create a fresh one containing just this entry.
        // (Loopback/LAN defaults are private IPs, which are skipped before the
        // whitelist is ever consulted, so nothing protective is lost.)
        @mkdir(dirname($yamlPath), 0775, true);
        if (file_put_contents($yamlPath, "whitelist:\n  - '$ip'\n") !== false) {
            echo "✓ Created $yamlPath with $ip whitelisted\n";
            echo "  (Remove this entry once you no longer need it.)\n";
        } else {
            fwrite(STDERR, "Warning: could not create $yamlPath — add the IP to the whitelist manually.\n");
        }
        exit($removed > 0 ? 0 : 1);
    }

    if (!is_writable($yamlPath)) {
        fwrite(STDERR, "Warning: cannot write to $yamlPath — add the IP to the whitelist manually.\n");
        exit($removed > 0 ? 0 : 1);
    }

    $yaml = file_get_contents($yamlPath);
    // Already present? Match the IP as a standalone token so bare block-scalar
    // entries (e.g. "  203.0.113.5") and quoted/list entries are all detected.
    if (preg_match('/(^|[\s\'"\-])' . preg_quote($ip, '/') . '($|[\s\'"])/m', $yaml)) {
        echo "Info: $ip is already in the whitelist.\n";
    } else {
        $updated = appendToWhitelist($yaml, $ip);
        if ($updated !== null) {
            file_put_contents($yamlPath, $updated);
            echo "✓ Added $ip to whitelist in $yamlPath\n";
            echo "  (Remove this entry once you no longer need it.)\n";
        } else {
            fwrite(STDERR, "Warning: could not locate 'whitelist:' key in $yamlPath — add manually.\n");
        }
    }
}

exit($removed > 0 ? 0 : 1);

/**
 * Append an IP to the `whitelist:` section, handling both the block-scalar
 * form (`whitelist: |` with bare indented IPs — the shipped default) and the
 * YAML list form (`- 1.2.3.4`). Returns the updated YAML, or null if no
 * `whitelist:` key was found.
 */
function appendToWhitelist(string $yaml, string $ip): ?string
{
    $lines = explode("\n", $yaml);
    $count = count($lines);

    for ($i = 0; $i < $count; $i++) {
        if (!preg_match('/^(\s*)whitelist:\s*(.*)$/', $lines[$i], $m)) {
            continue;
        }
        $baseIndent  = $m[1];
        $inlineValue = trim($m[2]);
        $isBlockScalar = $inlineValue !== '' && ($inlineValue[0] === '|' || $inlineValue[0] === '>');
        $childIndent = null;
        $isList      = false;
        $lastChild   = $i;

        // Walk the block: lines indented deeper than the `whitelist:` key.
        for ($j = $i + 1; $j < $count; $j++) {
            if (trim($lines[$j]) === '') {
                continue; // tolerate blank lines without ending the block
            }
            if (!preg_match('/^(\s+)\S/', $lines[$j], $im) || strlen($im[1]) <= strlen($baseIndent)) {
                break; // dedent → next key, block ended
            }
            if ($childIndent === null) {
                $childIndent = $im[1];
                $isList      = str_starts_with(ltrim($lines[$j]), '- ');
            }
            $lastChild = $j;
        }

        // With no existing entries, emit a list item unless it's a `|`/`>` block
        // scalar — appending a bare scalar to an empty key would parse as a
        // string, not a one-item list.
        if ($childIndent === null && !$isBlockScalar) {
            $isList = true;
        }

        $indent  = $childIndent ?? ($baseIndent . '  ');
        $newLine = $isList ? ($indent . "- '" . $ip . "'") : ($indent . $ip);
        array_splice($lines, $lastChild + 1, 0, $newLine);

        return implode("\n", $lines);
    }

    return null;
}
