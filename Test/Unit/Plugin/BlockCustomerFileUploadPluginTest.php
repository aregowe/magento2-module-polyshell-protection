<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

use Magento\Customer\Model\FileProcessor;
use Magento\Framework\Exception\LocalizedException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Plugin\BlockCustomerFileUploadPlugin;

class BlockCustomerFileUploadPluginTest extends TestCase
{
    use ThrowsOnDeprecationTrait;

    private BlockCustomerFileUploadPlugin $plugin;

    /** @var Logger&MockObject */
    private Logger $logger;

    protected function setUp(): void
    {
        $this->throwOnDeprecation(\Aregowe\PolyShellProtection\Plugin\BlockCustomerFileUploadPlugin::class, 'entityTypeCodeProperty');
        $this->logger = $this->createMock(Logger::class);
        $sanitizer = new SecurityLogSanitizer();

        $this->plugin = new BlockCustomerFileUploadPlugin(
            $this->logger,
            $sanitizer
        );
    }

    /**
     * @dataProvider blockedEntityTypeProvider
     */
    public function testSaveTemporaryFileBlockedForDangerousEntityTypes(string $entityType): void
    {
        $subject = $this->createFileProcessorWithEntityType($entityType);

        $this->logger->expects($this->once())
            ->method('warning')
            ->with(
                $this->stringContains('Blocked customer file upload attempt'),
                $this->anything()
            );

        $this->expectException(LocalizedException::class);
        $this->expectExceptionMessage('File uploads to this attribute type are not permitted.');

        $this->plugin->beforeSaveTemporaryFile($subject, 'custom_attributes[file_field]');
    }

    /**
     * @dataProvider blockedEntityTypeProvider
     */
    public function testMoveTemporaryFileBlockedForDangerousEntityTypes(string $entityType): void
    {
        $subject = $this->createFileProcessorWithEntityType($entityType);

        $this->expectException(LocalizedException::class);
        $this->expectExceptionMessage('File operations on this attribute type are not permitted.');

        $this->plugin->beforeMoveTemporaryFile($subject, 'gg');
    }

    public static function blockedEntityTypeProvider(): array
    {
        return [
            'customer_address' => ['customer_address'],
            'customer_addresses' => ['customer_addresses'],
            'custom_options' => ['custom_options'],
        ];
    }

    public function testSaveTemporaryFileAllowedForSafeEntityTypes(): void
    {
        $subject = $this->createFileProcessorWithEntityType('customer');

        $this->logger->expects($this->never())->method('warning');

        $result = $this->plugin->beforeSaveTemporaryFile($subject, 'avatar');
        $this->assertSame(['avatar'], $result);
    }

    public function testMoveTemporaryFileAllowedForSafeEntityTypes(): void
    {
        $subject = $this->createFileProcessorWithEntityType('customer');

        $result = $this->plugin->beforeMoveTemporaryFile($subject, 'photo.jpg');
        $this->assertSame(['photo.jpg'], $result);
    }

    /**
     * Create a FileProcessor mock with entityTypeCode property set via reflection.
     */
    private function createFileProcessorWithEntityType(string $entityTypeCode): FileProcessor
    {
        $subject = $this->createMock(FileProcessor::class);

        // The plugin reads the private property via reflection, but on a mock
        // the property doesn't exist. We need a real-ish approach.
        // Since we're mocking, we'll use a partial mock with a real property.
        $reflection = new \ReflectionClass(FileProcessor::class);
        if ($reflection->hasProperty('entityTypeCode')) {
            // Create a real instance isn't practical due to constructor deps,
            // so test the isBlockedEntityType logic via the public method behavior.
            // For the mock, we'll set the property on the mock object.
            $prop = $reflection->getProperty('entityTypeCode');
            $prop->setValue($subject, $entityTypeCode);
        }

        return $subject;
    }
}
