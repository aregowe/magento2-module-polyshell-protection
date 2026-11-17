<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Exception\InputException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Model\AttackPatternDetector;
use Aregowe\PolyShellProtection\Model\FileUploadGuard;
use Aregowe\PolyShellProtection\Model\PolyglotFileDetector;

class FileUploadGuardTest extends TestCase
{
    private FileUploadGuard $guard;

    /** @var ScopeConfigInterface|\PHPUnit\Framework\MockObject\MockObject */
    private ScopeConfigInterface $scopeConfig;

    protected function setUp(): void
    {
        $this->scopeConfig = $this->createMock(ScopeConfigInterface::class);
        $this->scopeConfig->method('getValue')
            ->willReturnMap([
                [FileUploadGuard::XML_PATH_ADDITIONAL_EXTENSIONS, 'default', null, ''],
                [FileUploadGuard::XML_PATH_ADDITIONAL_BLOCKED_EXTENSIONS, 'default', null, ''],
            ]);

        $this->guard = new FileUploadGuard(
            new PolyglotFileDetector(),
            new AttackPatternDetector(),
            $this->scopeConfig
        );
    }

    /**
     * Create a guard with specific admin-configured additional extensions and/or blocked extensions.
     */
    private function createGuardWithConfig(string $allowedExtras = '', string $blockedExtras = ''): FileUploadGuard
    {
        $scopeConfig = $this->createMock(ScopeConfigInterface::class);
        $scopeConfig->method('getValue')
            ->willReturnMap([
                [FileUploadGuard::XML_PATH_ADDITIONAL_EXTENSIONS, 'default', null, $allowedExtras],
                [FileUploadGuard::XML_PATH_ADDITIONAL_BLOCKED_EXTENSIONS, 'default', null, $blockedExtras],
            ]);

        return new FileUploadGuard(
            new PolyglotFileDetector(),
            new AttackPatternDetector(),
            $scopeConfig
        );
    }

    /**
     * Convenience alias for tests that only configure the allowlist.
     */
    private function createGuardWithAdditionalExtensions(string $configValue): FileUploadGuard
    {
        return $this->createGuardWithConfig($configValue);
    }

    public function testAllowsSafePngName(): void
    {
        $this->guard->assertSafeFileName('customer-photo.PNG');

        $this->assertTrue(true);
    }

    public function testBlocksUnicodeEscapedPhpExtension(): void
    {
        $this->expectException(InputException::class);

        $this->guard->assertSafeFileName('avatar\\u002ephp');
    }

    public function testBlocksPercentEncodedPhpExtension(): void
    {
        $this->expectException(InputException::class);

        $this->guard->assertSafeFileName('invoice%2ephp');
    }

    public function testBlocksDisallowedExtensionOutsideAllowlist(): void
    {
        $this->expectException(InputException::class);

        $this->guard->assertSafeFileName('archive.tar');
    }

    // ========================================================================
    // inferExtensionFromMimeType() — centralized MIME inference
    // ========================================================================

    /**
     * @dataProvider validMimeInferenceProvider
     */
    #[DataProvider('validMimeInferenceProvider')]
    public function testInferExtensionFromMimeTypeReturnsExpected(
        string $mimeType,
        string $expectedExtension
    ): void {
        $this->assertSame(
            $expectedExtension,
            FileUploadGuard::inferExtensionFromMimeType($mimeType)
        );
    }

    public static function validMimeInferenceProvider(): array
    {
        return [
            'image/jpeg' => ['image/jpeg', 'jpg'],
            'image/jpg' => ['image/jpg', 'jpg'],
            'image/png' => ['image/png', 'png'],
            'image/gif' => ['image/gif', 'gif'],
            'image/webp' => ['image/webp', 'webp'],
            'image/bmp' => ['image/bmp', 'bmp'],
            'image/heic' => ['image/heic', 'heic'],
            'image/heif maps to heic' => ['image/heif', 'heic'],
            'image/x-ms-bmp maps to bmp' => ['image/x-ms-bmp', 'bmp'],
            'charset parameter stripped' => ['image/jpeg; charset=utf-8', 'jpg'],
            'leading/trailing whitespace' => ['  image/png  ', 'png'],
            'case insensitive' => ['IMAGE/JPEG', 'jpg'],
            'mixed case with parameter' => ['Image/Gif; boundary=something', 'gif'],
        ];
    }

    /**
     * @dataProvider invalidMimeInferenceProvider
     */
    #[DataProvider('invalidMimeInferenceProvider')]
    public function testInferExtensionFromMimeTypeReturnsNull(?string $mimeType): void
    {
        $this->assertNull(FileUploadGuard::inferExtensionFromMimeType($mimeType));
    }

    public static function invalidMimeInferenceProvider(): array
    {
        return [
            'null' => [null],
            'empty string' => [''],
            'whitespace only' => ['   '],
            'application/x-php' => ['application/x-php'],
            'text/html' => ['text/html'],
            'application/octet-stream' => ['application/octet-stream'],
            'text/plain' => ['text/plain'],
            'video/mp4' => ['video/mp4'],
            'application/pdf' => ['application/pdf'],
        ];
    }

    public function testInferExtensionForFileNameReturnsNormalizedResult(): void
    {
        $result = $this->guard->inferExtensionForFileName('53298390_0', 'image/jpeg');

        $this->assertSame(['53298390_0.jpg', 'jpg'], $result);
    }

    public function testInferExtensionForFileNameReturnsNullForUnknownMime(): void
    {
        $result = $this->guard->inferExtensionForFileName('somefile', 'application/pdf');

        $this->assertNull($result);
    }

    public function testInferExtensionForFileNameReturnsNullForNullMime(): void
    {
        $result = $this->guard->inferExtensionForFileName('somefile', null);

        $this->assertNull($result);
    }

    public function testInferExtensionForFileNameTrimsTrailingDots(): void
    {
        $result = $this->guard->inferExtensionForFileName('photo...', 'image/png');

        $this->assertSame(['photo.png', 'png'], $result);
    }

    public function testInferExtensionForFileNameThrowsOnUnsafeName(): void
    {
        $this->expectException(InputException::class);

        $this->guard->inferExtensionForFileName('shell.php', 'image/jpeg');
    }

    // ========================================================================
    // RAR extension support
    // ========================================================================

    public function testAllowsRarExtension(): void
    {
        $this->guard->assertSafeFileName('archive.rar');

        $this->assertTrue(true);
    }

    public function testRarInBaseAllowedExtensions(): void
    {
        $this->assertArrayHasKey('rar', FileUploadGuard::BASE_ALLOWED_EXTENSIONS);
    }

    // ========================================================================
    // getAllowedExtensions() — base + admin-configured merge
    // ========================================================================

    public function testGetAllowedExtensionsReturnsBaseWhenNoConfig(): void
    {
        $extensions = $this->guard->getAllowedExtensions();

        $this->assertSame(FileUploadGuard::BASE_ALLOWED_EXTENSIONS, $extensions);
    }

    public function testGetAllowedExtensionsMergesAdminConfiguredExtensions(): void
    {
        $guard = $this->createGuardWithAdditionalExtensions('ai, psd, svg');

        $extensions = $guard->getAllowedExtensions();

        $this->assertArrayHasKey('ai', $extensions);
        $this->assertArrayHasKey('psd', $extensions);
        $this->assertArrayHasKey('svg', $extensions);
        // Base extensions still present
        $this->assertArrayHasKey('pdf', $extensions);
        $this->assertArrayHasKey('zip', $extensions);
    }

    public function testGetAllowedExtensionsLowercasesAdminInput(): void
    {
        $guard = $this->createGuardWithAdditionalExtensions('AI, PSD, Svg');

        $extensions = $guard->getAllowedExtensions();

        $this->assertArrayHasKey('ai', $extensions);
        $this->assertArrayHasKey('psd', $extensions);
        $this->assertArrayHasKey('svg', $extensions);
    }

    public function testGetAllowedExtensionsIgnoresEmptyEntries(): void
    {
        $guard = $this->createGuardWithAdditionalExtensions('ai, , ,psd');

        $extensions = $guard->getAllowedExtensions();

        $this->assertArrayHasKey('ai', $extensions);
        $this->assertArrayHasKey('psd', $extensions);
        // Count should be base + 2 new ones, no empty keys
        $this->assertArrayNotHasKey('', $extensions);
    }

    public function testGetAllowedExtensionsRejectsBlockedExtensions(): void
    {
        $guard = $this->createGuardWithAdditionalExtensions('php, phtml, exe, ai');

        $extensions = $guard->getAllowedExtensions();

        $this->assertArrayNotHasKey('php', $extensions);
        $this->assertArrayNotHasKey('phtml', $extensions);
        $this->assertArrayNotHasKey('exe', $extensions);
        // Safe extension still added
        $this->assertArrayHasKey('ai', $extensions);
    }

    public function testGetAllowedExtensionsRejectsAllBlockedPatterns(): void
    {
        $guard = $this->createGuardWithAdditionalExtensions(
            'phar, pht, pl, py, cgi, sh, asp, aspx, jsp, js, bat, cmd, vbs, ps1, jar, msi, inc, module, phps'
        );

        $extensions = $guard->getAllowedExtensions();

        foreach (['phar', 'pht', 'pl', 'py', 'cgi', 'sh', 'asp', 'aspx', 'jsp', 'js', 'bat', 'cmd', 'vbs', 'ps1', 'jar', 'msi', 'inc', 'module', 'phps'] as $blocked) {
            $this->assertArrayNotHasKey($blocked, $extensions, "Blocked extension '$blocked' should not be allowed");
        }
    }

    public function testGetAllowedExtensionsHandlesWhitespaceOnlyConfig(): void
    {
        $guard = $this->createGuardWithAdditionalExtensions('   ');

        $this->assertSame(FileUploadGuard::BASE_ALLOWED_EXTENSIONS, $guard->getAllowedExtensions());
    }

    public function testGetAllowedExtensionsDeduplicatesBaseExtensions(): void
    {
        $guard = $this->createGuardWithAdditionalExtensions('pdf, zip, jpg');

        $extensions = $guard->getAllowedExtensions();

        // Should not break, just overwrites with same true value
        $this->assertArrayHasKey('pdf', $extensions);
        $this->assertSame(FileUploadGuard::BASE_ALLOWED_EXTENSIONS, $extensions);
    }

    public function testAssertSafeFileNameAllowsAdminConfiguredExtension(): void
    {
        $guard = $this->createGuardWithAdditionalExtensions('ai');

        $guard->assertSafeFileName('design.ai');

        $this->assertTrue(true);
    }

    public function testAssertSafeFileNameBlocksUnconfiguredExtension(): void
    {
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file extension is not allowed.');

        $this->guard->assertSafeFileName('design.ai');
    }

    // ========================================================================
    // getBlockedExtensions() — base + admin-configured blocklist
    // ========================================================================

    public function testGetBlockedExtensionsReturnsBaseWhenNoConfig(): void
    {
        $blocked = $this->guard->getBlockedExtensions();

        $this->assertSame(FileUploadGuard::BASE_BLOCKED_EXTENSIONS, $blocked);
    }

    public function testGetBlockedExtensionsMergesAdminConfiguredExtensions(): void
    {
        $guard = $this->createGuardWithConfig('', 'svg, swf, html');

        $blocked = $guard->getBlockedExtensions();

        $this->assertArrayHasKey('svg', $blocked);
        $this->assertArrayHasKey('swf', $blocked);
        $this->assertArrayHasKey('html', $blocked);
        // Base blocked extensions still present
        $this->assertArrayHasKey('php', $blocked);
        $this->assertArrayHasKey('exe', $blocked);
    }

    public function testGetBlockedExtensionsLowercasesAdminInput(): void
    {
        $guard = $this->createGuardWithConfig('', 'SVG, SWF, Html');

        $blocked = $guard->getBlockedExtensions();

        $this->assertArrayHasKey('svg', $blocked);
        $this->assertArrayHasKey('swf', $blocked);
        $this->assertArrayHasKey('html', $blocked);
    }

    public function testGetBlockedExtensionsIgnoresEmptyEntries(): void
    {
        $guard = $this->createGuardWithConfig('', 'svg, , , swf');

        $blocked = $guard->getBlockedExtensions();

        $this->assertArrayHasKey('svg', $blocked);
        $this->assertArrayHasKey('swf', $blocked);
        $this->assertArrayNotHasKey('', $blocked);
    }

    public function testGetBlockedExtensionsHandlesWhitespaceOnlyConfig(): void
    {
        $guard = $this->createGuardWithConfig('', '   ');

        $this->assertSame(FileUploadGuard::BASE_BLOCKED_EXTENSIONS, $guard->getBlockedExtensions());
    }

    public function testGetBlockedExtensionsDeduplicatesBaseExtensions(): void
    {
        $guard = $this->createGuardWithConfig('', 'php, exe, bat');

        $blocked = $guard->getBlockedExtensions();

        // Should not break, values just overwrite with same true
        $this->assertArrayHasKey('php', $blocked);
        $this->assertArrayHasKey('exe', $blocked);
        $this->assertArrayHasKey('bat', $blocked);
    }

    // ========================================================================
    // Blocklist overrides allowlist
    // ========================================================================

    public function testBlocklistOverridesAllowlist(): void
    {
        // Add svg to both allowed and blocked — blocked should win
        $guard = $this->createGuardWithConfig('svg', 'svg');

        $extensions = $guard->getAllowedExtensions();

        $this->assertArrayNotHasKey('svg', $extensions);
    }

    public function testBlocklistRemovesBaseAllowedExtension(): void
    {
        // Block pdf which is in BASE_ALLOWED_EXTENSIONS
        $guard = $this->createGuardWithConfig('', 'pdf');

        $extensions = $guard->getAllowedExtensions();

        $this->assertArrayNotHasKey('pdf', $extensions);
    }

    public function testBlocklistDoesNotAffectUnrelatedAllowedExtensions(): void
    {
        $guard = $this->createGuardWithConfig('ai', 'svg');

        $extensions = $guard->getAllowedExtensions();

        // ai should still be allowed
        $this->assertArrayHasKey('ai', $extensions);
        // svg should be blocked
        $this->assertArrayNotHasKey('svg', $extensions);
        // Base allowed should still be present
        $this->assertArrayHasKey('pdf', $extensions);
        $this->assertArrayHasKey('zip', $extensions);
    }

    public function testAssertSafeFileNameBlocksAdminBlocklistedExtension(): void
    {
        $guard = $this->createGuardWithConfig('svg', 'svg');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file extension is not allowed for security reasons.');

        $guard->assertSafeFileName('logo.svg');
    }

    public function testAssertSafeFileNameBlocksAdminBlocklistedBaseExtension(): void
    {
        $guard = $this->createGuardWithConfig('', 'pdf');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file extension is not allowed for security reasons.');

        $guard->assertSafeFileName('document.pdf');
    }

    public function testBaseBlockedExtensionsConstantContainsAllExpectedKeys(): void
    {
        $expected = [
            'asp', 'aspx', 'bat', 'cgi', 'cmd', 'com', 'dll', 'exe',
            'inc', 'jar', 'js', 'jsp', 'mjs', 'module', 'msi', 'phar',
            'php', 'phps', 'pht', 'phtml', 'phtm', 'pl', 'ps1', 'py',
            'sh', 'shtml', 'so', 'vbs',
        ];

        foreach ($expected as $ext) {
            $this->assertArrayHasKey(
                $ext,
                FileUploadGuard::BASE_BLOCKED_EXTENSIONS,
                "Expected '$ext' in BASE_BLOCKED_EXTENSIONS"
            );
        }
    }

    // ========================================================================
    // .inc, .module, .phps — newly blocked extensions (issue #4)
    // ========================================================================

    /**
     * @dataProvider newlyBlockedExtensionsProvider
     */
    #[DataProvider('newlyBlockedExtensionsProvider')]
    public function testBlocksNewlyAddedDangerousExtensions(string $filename): void
    {
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file extension is not allowed for security reasons.');

        $this->guard->assertSafeFileName($filename);
    }

    public static function newlyBlockedExtensionsProvider(): array
    {
        return [
            '.inc file' => ['config.inc'],
            '.module file' => ['custom.module'],
            '.phps file' => ['info.phps'],
            '.inc uppercase' => ['CONFIG.INC'],
            '.module uppercase' => ['CUSTOM.MODULE'],
            '.phps uppercase' => ['INFO.PHPS'],
        ];
    }

    /**
     * @dataProvider doubleExtensionBypassProvider
     */
    #[DataProvider('doubleExtensionBypassProvider')]
    public function testBlocksDoubleExtensionBypassWithNewExtensions(string $filename): void
    {
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Uploaded file extension is not allowed for security reasons.');

        $this->guard->assertSafeFileName($filename);
    }

    /**
     * Verifies that double-extension attacks using .inc, .module, .phps
     * are caught by BLOCKED_EXTENSION_PATTERN. These were reported in
     * issue #4 as real attack vectors in the wild (e.g. file.inc..png
     * normalizes to file.inc.png).
     */
    public static function doubleExtensionBypassProvider(): array
    {
        return [
            '.inc.png double-extension' => ['bobwashere_PNG.inc.png'],
            '.inc.jpg double-extension' => ['shell.inc.jpg'],
            '.module.gif double-extension' => ['backdoor.module.gif'],
            '.phps.png double-extension' => ['source.phps.png'],
            '.phps.jpg double-extension' => ['leak.phps.jpg'],
        ];
    }
}
