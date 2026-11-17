<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Plugin;

use Magento\Framework\App\ActionInterface;
use Magento\Framework\Controller\ResultFactory;
use Magento\Framework\Controller\ResultInterface;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Logger\Logger;

/**
 * Blocks the CustomerCustomAttributes file upload controllers entirely.
 *
 * Both Address\File\Upload and Customer\File\Upload extend AbstractUploadFile.
 * This plugin intercepts execute() on the abstract parent, blocking all
 * customer EAV file attribute uploads at the controller entry point.
 *
 * Defense-in-depth layer above BlockCustomerFileUploadPlugin on FileProcessor.
 */
class BlockCustomerAttributeFileUploadControllerPlugin
{
    private ResultFactory $resultFactory;

    private Logger $logger;

    private SecurityLogSanitizer $logSanitizer;

    public function __construct(
        ResultFactory $resultFactory,
        Logger $logger,
        SecurityLogSanitizer $logSanitizer
    ) {
        $this->resultFactory = $resultFactory;
        $this->logger = $logger;
        $this->logSanitizer = $logSanitizer;
    }

    /**
     * Intercept and block all customer attribute file upload controller executions.
     *
     * Returns a JSON error response matching the controller's expected format
     * so the frontend handles it gracefully.
     *
     * @param ActionInterface $subject
     * @param callable $proceed
     * @return ResultInterface
     */
    public function aroundExecute(ActionInterface $subject, callable $proceed): ResultInterface
    {
        $controllerClass = get_class($subject);

        $this->logger->warning(
            'PolyShellProtection: Blocked customer attribute file upload at controller',
            [
                'controller' => $this->logSanitizer->sanitizeString($controllerClass),
            ]
        );

        /** @var \Magento\Framework\Controller\Result\Json $result */
        $result = $this->resultFactory->create(ResultFactory::TYPE_JSON);
        $result->setData([
            'error' => true,
            'message' => (string) __('File uploads to customer attributes are not permitted.'),
        ]);

        return $result;
    }
}
