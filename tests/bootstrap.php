<?php
/**
 * Test bootstrap: loads vendor autoload and defines minimal Grav stubs
 * so plugin classes can be loaded without a full Grav installation.
 *
 * PHP requires all namespace declarations to use block syntax when mixing
 * namespaced and global code in a single file.
 */

// ── Global code (autoloader + plugin file) ───────────────────────────────────
namespace {
    require_once __DIR__ . '/../vendor/autoload.php';
    require_once __DIR__ . '/../grvhulk.php';
}

// ── Grav\Common\Filesystem\Folder ───────────────────────────────────────────
namespace Grav\Common\Filesystem {
    class Folder
    {
        public static function create(string $path, int $mode = 0777): void
        {
            if (!is_dir($path)) {
                mkdir($path, $mode, true);
            }
        }
    }
}

// ── Grav\Common\Plugin, Utils, Grav ─────────────────────────────────────────
namespace Grav\Common {
    abstract class Plugin
    {
        protected array $_config = [];

        public static function getSubscribedEvents(): array
        {
            return [];
        }

        protected function isAdmin(): bool
        {
            return false;
        }

        protected function enable(array $events): void {}

        public function config(): array
        {
            return $this->_config;
        }
    }

    class Utils
    {
        public static function verifyNonce(string $nonce, string $action): bool
        {
            return true;
        }
    }

    class Grav extends \ArrayObject
    {
        private static ?self $instance = null;

        public static function instance(): self
        {
            if (self::$instance === null) {
                self::$instance = new self();
            }
            return self::$instance;
        }
    }
}

// ── Grav\Framework\Psr7\Response ────────────────────────────────────────────
namespace Grav\Framework\Psr7 {
    class Response
    {
        public function __construct(
            public readonly int $status = 200,
            public readonly array $headers = [],
            public readonly string $body = ''
        ) {}
    }
}

// ── RocketTheme\Toolbox\Event\Event ─────────────────────────────────────────
namespace RocketTheme\Toolbox\Event {
    class Event extends \ArrayObject {}
}
