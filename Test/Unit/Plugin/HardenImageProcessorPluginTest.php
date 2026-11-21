<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Api\ImageProcessor;
use Magento\Framework\Exception\InputException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\FileUploadGuard;
use Aregowe\PolyShellProtection\Model\PolyglotFileDetector;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Plugin\HardenImageProcessorPlugin;

class HardenImageProcessorPluginTest extends TestCase
{
    use ThrowsOnDeprecationTrait;

    private HardenImageProcessorPlugin $plugin;

    /** @var Logger|\PHPUnit\Framework\MockObject\MockObject */
    private Logger $logger;

    /** @var PolyglotFileDetector|\PHPUnit\Framework\MockObject\MockObject */
    private PolyglotFileDetector $polyglotDetector;

    protected function setUp(): void
    {
        $this->throwOnDeprecation(\Aregowe\PolyShellProtection\Plugin\HardenImageProcessorPlugin::class, 'uploaderProperty');
        $this->polyglotDetector = $this->createMock(PolyglotFileDetector::class);
        $this->logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $fileUploadGuard = $this->createMock(FileUploadGuard::class);
        $fileUploadGuard->method('inferExtensionForFileName')->willReturnCallback(
            static function (string $fileName, ?string $mimeType): ?array {
                $ext = FileUploadGuard::inferExtensionFromMimeType($mimeType);
                if ($ext === null) {
                    return null;
                }
                return [rtrim($fileName, " \t\n\r\0\x0B.") . '.' . $ext, $ext];
            }
        );
        $sanitizer = new SecurityLogSanitizer();

        $this->plugin = new HardenImageProcessorPlugin(
            $fileUploadGuard,
            $this->polyglotDetector,
            $this->logger,
            $sanitizer
        );
    }

    public function testValidImagePassesThrough(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('photo.jpg');
        $imageContent->method('getBase64EncodedData')->willReturn(base64_encode('safe data'));

        $subject = $this->createMock(ImageProcessor::class);

        $result = $this->plugin->beforeProcessImageContent($subject, 'catalog', $imageContent);

        $this->assertSame(['catalog', $imageContent], $result);
    }

    /**
     * Verifies all allowed image extensions pass validation.
     * Covers MarkShust's original allowlist (jpg, jpeg, gif, png) plus expanded set.
     *
     * @dataProvider allowedExtensionsProvider
     */
    #[DataProvider('allowedExtensionsProvider')]
    public function testAllAllowedExtensionsPass(string $extension): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('image.' . $extension);
        $imageContent->method('getBase64EncodedData')->willReturn(base64_encode('safe data'));

        $subject = $this->createMock(ImageProcessor::class);

        $result = $this->plugin->beforeProcessImageContent($subject, 'catalog', $imageContent);

        $this->assertSame(['catalog', $imageContent], $result);
    }

    public static function allowedExtensionsProvider(): array
    {
        return [
            'jpg'  => ['jpg'],
            'jpeg' => ['jpeg'],
            'gif'  => ['gif'],
            'png'  => ['png'],
            'webp' => ['webp'],
            'bmp'  => ['bmp'],
            'heic' => ['heic'],
        ];
    }

    /**
     * Verifies dangerous extensions are blocked.
     * Covers the full blocked extension pattern including common webshell extensions.
     *
     * @dataProvider dangerousExtensionsProvider
     */
    #[DataProvider('dangerousExtensionsProvider')]
    public function testDangerousExtensionsBlocked(string $filename): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn($filename);

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }

    public static function dangerousExtensionsProvider(): array
    {
        return [
            'php'   => ['shell.php'],
            'phtml' => ['shell.phtml'],
            'phar'  => ['shell.phar'],
            'pht'   => ['shell.pht'],
            'asp'   => ['shell.asp'],
            'aspx'  => ['shell.aspx'],
            'jsp'   => ['shell.jsp'],
            'exe'   => ['payload.exe'],
            'sh'    => ['script.sh'],
        ];
    }

    public function testEmptyFilenameBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('');

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Image file name is required.');

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }

    public function testNullFilenameBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn(null);

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Image file name is required.');

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }

    public function testNoExtensionBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('noext');
        $imageContent->method('getType')->willReturn(null);

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('Image file must include a valid file extension.');

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }

    public function testNoExtensionWithJpegMimePasses(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('53298390_0');
        $imageContent->method('getType')->willReturn('image/jpeg');
        $imageContent->method('getBase64EncodedData')->willReturn(base64_encode('safe data'));
        $imageContent->expects($this->once())
            ->method('setName')
            ->with('53298390_0.jpg')
            ->willReturnSelf();

        $subject = $this->createMock(ImageProcessor::class);

        $result = $this->plugin->beforeProcessImageContent($subject, 'tmp/catalog/product', $imageContent);

        $this->assertSame(['tmp/catalog/product', $imageContent], $result);
    }

    public function testNonImageExtensionBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('shell.php');

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('not allowed');

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }

    public function testDoubleExtensionBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('backdoor.php.png');

        $this->logger->expects($this->once())->method('warning');
        $this->expectException(InputException::class);
        $this->expectExceptionMessage('blocked extension pattern');

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }

    public function testPolyglotContentBlocked(): void
    {
        $imageContent = $this->createMock(ImageContentInterface::class);
        $imageContent->method('getName')->willReturn('polyglot.png');
        $imageContent->method('getBase64EncodedData')
            ->willReturn(base64_encode('png with php'));

        $this->polyglotDetector->expects($this->once())
            ->method('assertNotPolyglot')
            ->willThrowException(new InputException(__('Polyglot detected')));

        $this->expectException(InputException::class);

        $this->plugin->beforeProcessImageContent(
            $this->createMock(ImageProcessor::class),
            'catalog',
            $imageContent
        );
    }
}
