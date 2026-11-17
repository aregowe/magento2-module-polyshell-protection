<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

use Magento\Framework\App\ResponseInterface;
use Magento\Framework\Exception\NotFoundException;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use Magento\MediaStorage\App\Media;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Model\SecurityPathGuard;
use Aregowe\PolyShellProtection\Plugin\BlockSuspiciousMediaAppPathPlugin;

class BlockSuspiciousMediaAppPathPluginTest extends TestCase
{
    /** @var Logger|\PHPUnit\Framework\MockObject\MockObject */
    private Logger $logger;

    /** @var SecurityPathGuard|\PHPUnit\Framework\MockObject\MockObject */
    private SecurityPathGuard $pathGuard;

    private BlockSuspiciousMediaAppPathPlugin $plugin;

    protected function setUp(): void
    {
        $this->logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $remoteAddress = $this->createMock(RemoteAddress::class);
        $remoteAddress->method('getRemoteAddress')->willReturn('127.0.0.1');
        $this->pathGuard = $this->createMock(SecurityPathGuard::class);
        $sanitizer = new SecurityLogSanitizer();

        $this->plugin = new BlockSuspiciousMediaAppPathPlugin(
            $this->logger,
            $remoteAddress,
            $this->pathGuard,
            $sanitizer
        );
    }

    public function testSafePathPassesThrough(): void
    {
        // Media mock — reflection will fail to find relativeFileName on the mock
        // subclass, so getRelativeFileName returns '' and the request passes through.
        $media = $this->createMock(Media::class);
        $expectedResponse = $this->createMock(ResponseInterface::class);

        $proceed = function () use ($expectedResponse) {
            return $expectedResponse;
        };

        $result = $this->plugin->aroundLaunch($media, $proceed);

        $this->assertSame($expectedResponse, $result);
    }

    public function testBlockedPathThrowsNotFoundException(): void
    {
        // Create a real-ish Media with the private property set via reflection.
        // Since Media has complex constructor deps, we use a mock and set the
        // property on it using the parent class reflector.
        $media = $this->createMock(Media::class);

        try {
            $reflection = new \ReflectionClass(Media::class);
            if ($reflection->hasProperty('relativeFileName')) {
                $prop = $reflection->getProperty('relativeFileName');
                $prop->setValue($media, 'custom_options/quote/shell.php');
            }
        } catch (\ReflectionException $e) {
            $this->markTestSkipped('Cannot set relativeFileName on Media mock: ' . $e->getMessage());
        }

        $this->pathGuard->method('isBlockedMediaRelativePath')->willReturn(true);
        $this->logger->expects($this->once())->method('warning');

        $proceed = function () {
            $this->fail('Proceed should not be called for blocked paths');
        };

        $this->expectException(NotFoundException::class);

        $this->plugin->aroundLaunch($media, $proceed);
    }
}
