<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

use Magento\Framework\App\ActionInterface;
use Magento\Framework\Controller\Result\Json as JsonResult;
use Magento\Framework\Controller\ResultFactory;
use PHPUnit\Framework\TestCase;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Plugin\BlockCustomerAttributeFileUploadControllerPlugin;

class BlockCustomerAttributeFileUploadControllerPluginTest extends TestCase
{
    public function testBlocksAllUploadsWithJsonErrorResponse(): void
    {
        $jsonResult = $this->createMock(JsonResult::class);
        $jsonResult->expects($this->once())
            ->method('setData')
            ->with($this->callback(function (array $data) {
                return $data['error'] === true
                    && str_contains($data['message'], 'not permitted');
            }))
            ->willReturnSelf();

        $resultFactory = $this->createMock(ResultFactory::class);
        $resultFactory->expects($this->once())
            ->method('create')
            ->with(ResultFactory::TYPE_JSON)
            ->willReturn($jsonResult);

        $logger = $this->getMockBuilder(Logger::class)->disableOriginalConstructor()->getMock();
        $logger->expects($this->once())->method('warning');

        $sanitizer = new SecurityLogSanitizer();

        $plugin = new BlockCustomerAttributeFileUploadControllerPlugin(
            $resultFactory,
            $logger,
            $sanitizer
        );

        $subject = $this->createMock(ActionInterface::class);
        $proceed = function () {
            $this->fail('Proceed should not be called — plugin must block');
        };

        $result = $plugin->aroundExecute($subject, $proceed);

        $this->assertSame($jsonResult, $result);
    }
}
