<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Plugin;

use Magento\Customer\Model\FileProcessor;
use Magento\Framework\Exception\LocalizedException;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Logger\Logger;

/**
 * Blocks all file uploads processed through Customer FileProcessor
 * targeting sensitive directories (customer_address, customer_addresses, custom_options).
 *
 * This closes the upload-side gap where the Magento CustomerCustomAttributes
 * file upload controller (POST /customer_custom_attributes/address_file/upload)
 * writes directly to pub/media/customer_address/ via FileProcessor::saveTemporaryFile().
 */
class BlockCustomerFileUploadPlugin
{
    /**
     * Entity type codes that must be blocked from receiving any file uploads.
     */
    private const BLOCKED_ENTITY_TYPES = [
        'customer_address',
        'customer_addresses',
        'custom_options',
    ];

    private Logger $logger;

    private SecurityLogSanitizer $logSanitizer;

    private static ?\ReflectionProperty $entityTypeCodeProperty = null;

    public function __construct(
        Logger $logger,
        SecurityLogSanitizer $logSanitizer
    ) {
        $this->logger = $logger;
        $this->logSanitizer = $logSanitizer;
    }

    /**
     * Block saveTemporaryFile for dangerous entity types.
     *
     * FileProcessor is instantiated with an entityTypeCode that determines
     * the destination directory under pub/media/. We intercept the save
     * and hard-reject when the entity type targets a blocked path.
     *
     * @param FileProcessor $subject
     * @param string $fileId
     * @return array
     * @throws LocalizedException
     */
    public function beforeSaveTemporaryFile(FileProcessor $subject, $fileId): array
    {
        $entityTypeCode = $this->extractEntityTypeCode($subject);

        if ($this->isBlockedEntityType($entityTypeCode)) {
            $this->logger->warning(
                'PolyShellProtection: Blocked customer file upload attempt',
                [
                    'entity_type' => $this->logSanitizer->sanitizeString($entityTypeCode),
                    'file_id' => $this->logSanitizer->sanitizeString((string) $fileId),
                ]
            );

            throw new LocalizedException(
                __('File uploads to this attribute type are not permitted.')
            );
        }

        return [$fileId];
    }

    /**
     * Block moveTemporaryFile for dangerous entity types.
     *
     * Defense-in-depth: even if a file somehow bypasses saveTemporaryFile
     * (e.g. written by another code path), block the move from tmp/ to
     * the permanent location.
     *
     * @param FileProcessor $subject
     * @param string $fileName
     * @return array
     * @throws LocalizedException
     */
    public function beforeMoveTemporaryFile(FileProcessor $subject, $fileName): array
    {
        $entityTypeCode = $this->extractEntityTypeCode($subject);

        if ($this->isBlockedEntityType($entityTypeCode)) {
            $this->logger->warning(
                'PolyShellProtection: Blocked customer file move attempt',
                [
                    'entity_type' => $this->logSanitizer->sanitizeString($entityTypeCode),
                    'file_name' => $this->logSanitizer->sanitizeString((string) $fileName),
                ]
            );

            throw new LocalizedException(
                __('File operations on this attribute type are not permitted.')
            );
        }

        return [$fileName];
    }

    /**
     * Extract the private entityTypeCode from FileProcessor via reflection.
     *
     * FileProcessor stores its target directory as a private property set
     * during construction. We need to read it to determine if this instance
     * is targeting a dangerous path.
     */
    private function extractEntityTypeCode(FileProcessor $subject): string
    {
        try {
            if (self::$entityTypeCodeProperty === null) {
                $reflection = new \ReflectionClass(FileProcessor::class);
                self::$entityTypeCodeProperty = $reflection->getProperty('entityTypeCode');
            }
            return (string) self::$entityTypeCodeProperty->getValue($subject);
        } catch (\ReflectionException $e) {
            // If reflection fails, block by default — fail closed
            $this->logger->error(
                'PolyShellProtection: Could not read FileProcessor entityTypeCode, blocking by default',
                ['error' => $e->getMessage()]
            );
            return 'unknown_blocked';
        }
    }

    private function isBlockedEntityType(string $entityTypeCode): bool
    {
        $normalized = strtolower(trim($entityTypeCode));

        foreach (self::BLOCKED_ENTITY_TYPES as $blocked) {
            if ($normalized === $blocked) {
                return true;
            }
        }

        // Also block if the entity type code is unknown (reflection failure)
        // This is fail-closed behavior
        if ($normalized === 'unknown_blocked') {
            return true;
        }

        return false;
    }
}
