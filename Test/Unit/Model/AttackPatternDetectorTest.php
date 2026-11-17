<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Model;

use Magento\Framework\Exception\InputException;
use Aregowe\PolyShellProtection\Model\AttackPatternDetector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class AttackPatternDetectorTest extends TestCase
{
    private AttackPatternDetector $detector;

    protected function setUp(): void
    {
        $this->detector = new AttackPatternDetector();
    }

    /**
     * Test that legitimate filenames pass — including words that previously
     * false-positived on overly broad regex (latest, contest, epoch, etc.).
     */
    public function testLegitimateFilenamePasses(): void
    {
        $this->detector->assertSafeFilename('profile-photo.jpg');
        $this->detector->assertSafeFilename('resume.pdf');
        $this->detector->assertSafeFilename('document_2024.xlsx');
        $this->detector->assertSafeFilename('latest.jpg');
        $this->detector->assertSafeFilename('contest.png');
        $this->detector->assertSafeFilename('greatest-hits.pdf');
        $this->detector->assertSafeFilename('epoch.jpg');
        $this->detector->assertSafeFilename('testimony.docx');
        $this->detector->assertSafeFilename('pocket-guide.pdf');
        $this->assertTrue(true);
    }

    /**
     * Test that known attack filenames are rejected.
     *
     * @dataProvider knownAttackFilenamesProvider
     */
    #[DataProvider('knownAttackFilenamesProvider')]
    public function testKnownAttackFilenamesRejected(string $filename): void
    {
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('not permitted');
        $this->detector->assertSafeFilename($filename);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function knownAttackFilenamesProvider(): array
    {
        return [
            'index.php' => ['index.php'],
            'json-shell.php' => ['json-shell.php'],
            'bypass.phtml' => ['bypass.phtml'],
            'accesson.php' => ['accesson.php'],
            'rce.php' => ['rce.php'],
            'shell.php' => ['shell.php'],
        ];
    }

    /**
     * Test that option_id + index.php pattern is rejected (780index.php).
     */
    public function testOptionIdIndexPatternRejected(): void
    {
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('suspicious pattern');
        
        $this->detector->assertSafeFilename('780index.php');
    }

    /**
     * Test that double-extension payloads are rejected (php.gif).
     */
    public function testDoubleExtensionRejected(): void
    {
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('suspicious pattern');
        
        $this->detector->assertSafeFilename('shell.php.gif');
    }

    /**
     * Test that exploit/test indicator filenames are rejected.
     *
     * @dataProvider exploitIndicatorProvider
     */
    #[DataProvider('exploitIndicatorProvider')]
    public function testExploitIndicatorsRejected(string $filename): void
    {
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('not permitted');

        $this->detector->assertSafeFilename($filename);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function exploitIndicatorProvider(): array
    {
        return [
            'ato_poc.html (exact match)' => ['ato_poc.html'],
            'test.php (exact match)' => ['test.php'],
            'poc_shell.jpg (pattern)' => ['poc_shell.jpg'],
            'test-upload.gif (pattern)' => ['test-upload.gif'],
            'exploit.pdf (word boundary)' => ['exploit.pdf'],
            'payload.png (word boundary)' => ['payload.png'],
        ];
    }

}
