<?php
namespace Grav\Plugin\Grvhulk\Tests;

use Grav\Plugin\GrvhulkPlugin;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class NormalizeAgentTypesTest extends TestCase
{
    private static array $defaults = [
        'AI Assistant',
        'AI Data Scraper',
        'AI Search Crawler',
        'Undocumented AI Agent',
    ];

    private function normalize(mixed $input): array
    {
        $ref = new ReflectionClass(GrvhulkPlugin::class);
        $method = $ref->getMethod('normalizeAgentTypes');
        $method->setAccessible(true);
        return $method->invoke(null, $input);
    }

    public function testEmptyArrayReturnsDefaults(): void
    {
        $this->assertSame(self::$defaults, $this->normalize([]));
    }

    public function testNullReturnsDefaults(): void
    {
        $this->assertSame(self::$defaults, $this->normalize(null));
    }

    public function testAssocMapWithSomeTrueFiltersSelected(): void
    {
        $input = [
            'AI Assistant'          => true,
            'AI Data Scraper'       => false,
            'AI Search Crawler'     => true,
            'Undocumented AI Agent' => false,
        ];
        $this->assertSame(['AI Assistant', 'AI Search Crawler'], $this->normalize($input));
    }

    public function testAssocMapAllFalseReturnsDefaults(): void
    {
        $input = [
            'AI Assistant'          => false,
            'AI Data Scraper'       => false,
            'AI Search Crawler'     => false,
            'Undocumented AI Agent' => false,
        ];
        $this->assertSame(self::$defaults, $this->normalize($input));
    }

    public function testSequentialArrayPassedThrough(): void
    {
        $input = ['AI Assistant', 'AI Data Scraper'];
        $this->assertSame($input, $this->normalize($input));
    }

    public function testAllFourDefaultsAsSequentialArray(): void
    {
        $this->assertSame(self::$defaults, $this->normalize(self::$defaults));
    }

    public function testSingleEntryAssocMap(): void
    {
        $this->assertSame(['AI Search Crawler'], $this->normalize(['AI Search Crawler' => true]));
    }
}
