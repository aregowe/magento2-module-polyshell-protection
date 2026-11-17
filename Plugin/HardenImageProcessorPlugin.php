<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Plugin;

use Magento\Framework\Api\Data\ImageContentInterface;
use Magento\Framework\Api\ImageProcessor;
use Magento\Framework\Api\Uploader;
use Magento\Framework\Exception\InputException;
use Aregowe\PolyShellProtection\Model\FileUploadGuard;
use Aregowe\PolyShellProtection\Model\PolyglotFileDetector;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Logger\Logger;

/**
 * Hardened extension enforcement on the framework-level ImageProcessor.
 *
 * ImageProcessor::processImageContent() creates an Uploader and saves the file
 * to disk. By default, Magento never calls setAllowedExtensions() on the Uploader,
 * meaning ANY file extension is accepted. This is the root cause of APSB25-94.
 *
 * This plugin integrates and supersedes MarkShust_PolyshellPatch's
 * ImageProcessorRestrictExtensions, which set the uploader to [jpg, jpeg, gif, png].
 * In addition to locking the uploader, this plugin:
 * - Performs filename validation with obfuscation detection BEFORE the save
 * - Scans the base64 content for embedded PHP/polyglot payloads
 * - Blocks files with no extension
 *
 * Original uploader-locking concept by Mark Shust (MarkShust_PolyshellPatch).
 */
class HardenImageProcessorPlugin
{
    private static ?\ReflectionProperty $uploaderProperty = null;

    private FileUploadGuard $fileUploadGuard;

    private PolyglotFileDetector $polyglotDetector;

    private Logger $logger;

    private SecurityLogSanitizer $logSanitizer;

    public function __construct(
        FileUploadGuard $fileUploadGuard,
        PolyglotFileDetector $polyglotDetector,
        Logger $logger,
        SecurityLogSanitizer $logSanitizer
    ) {
        $this->fileUploadGuard = $fileUploadGuard;
        $this->polyglotDetector = $polyglotDetector;
        $this->logger = $logger;
        $this->logSanitizer = $logSanitizer;
    }

    /**
     * Before processImageContent, enforce strict extension allowlist and validate content.
     *
     * @param ImageProcessor $subject
     * @param string $entityType
     * @param ImageContentInterface $imageContent
     * @return array
     * @throws InputException
     *
     * @SuppressWarnings(PHPMD.UnusedFormalParameter)
     */
    public function beforeProcessImageContent(
        ImageProcessor $subject,
        $entityType,
        $imageContent
    ): array {
        // Lock the subject's uploader to image-only extensions via reflection.
        // This avoids relying on DI shared=true singleton assumption.
        $this->lockSubjectUploaderExtensions($subject);

        $fileName = $imageContent->getName();

        // Block empty filenames
        if ($fileName === null || trim($fileName) === '') {
            $this->logBlock('empty filename', '', $entityType);
            throw new InputException(__('Image file name is required.'));
        }

        $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

        // For extension-less REST payloads, infer extension from claimed MIME type.
        if ($extension === '') {
            $mimeType = $imageContent->getType();
            $inferenceResult = $this->fileUploadGuard->inferExtensionForFileName($fileName, $mimeType);
            if ($inferenceResult === null) {
                $this->logBlock('no extension', $fileName, $entityType);
                throw new InputException(__('Image file must include a valid file extension.'));
            }

            [$fileName, $extension] = $inferenceResult;
            $imageContent->setName($fileName);
        }

        // Block non-image extensions
        if (!in_array($extension, FileUploadGuard::ALLOWED_IMAGE_EXTENSIONS, true)) {
            $this->logBlock('non-image extension: ' . $extension, $fileName, $entityType);
            throw new InputException(
                __('The image file extension "%1" is not allowed.', $extension)
            );
        }

        // Double-extension attack detection
        if (preg_match(FileUploadGuard::BLOCKED_EXTENSION_PATTERN, $fileName) === 1) {
            $this->logBlock('blocked extension pattern', $fileName, $entityType);
            throw new InputException(
                __('Image filename contains a blocked extension pattern.')
            );
        }

        // Scan base64-decoded content for embedded PHP
        $base64Content = $imageContent->getBase64EncodedData();
        if ($base64Content !== null && $base64Content !== '') {
            $decodedContent = base64_decode($base64Content, true);
            if ($decodedContent !== false && $decodedContent !== '') {
                $this->polyglotDetector->assertNotPolyglot($decodedContent, $fileName);
            }
        }

        return [$entityType, $imageContent];
    }

    private function logBlock(string $reason, string $fileName, mixed $entityType): void
    {
        $this->logger->warning(
            'PolyShellProtection: Blocked image upload at ImageProcessor',
            [
                'reason' => $reason,
                'filename' => $this->logSanitizer->sanitizeString($fileName),
                'entity_type' => $this->logSanitizer->sanitizeString((string) $entityType),
            ]
        );
    }

    /**
     * Access the subject's private $uploader property via reflection and
     * lock its allowed extensions. This is more robust than relying on
     * DI shared=true singleton behavior for the Uploader instance.
     */
    private function lockSubjectUploaderExtensions(ImageProcessor $subject): void
    {
        try {
            if (self::$uploaderProperty === null) {
                $reflection = new \ReflectionClass(ImageProcessor::class);
                self::$uploaderProperty = $reflection->getProperty('uploader');
            }
            $uploader = self::$uploaderProperty->getValue($subject);

            if ($uploader instanceof Uploader) {
                $uploader->setAllowedExtensions(FileUploadGuard::ALLOWED_IMAGE_EXTENSIONS);
            }
        } catch (\ReflectionException $e) {
            // Fail open — if reflection breaks, the other layers (ImageContentValidator
            // plugin, request path blocking) still enforce extension restrictions.
            $this->logger->warning(
                'PolyShellProtection: Could not lock ImageProcessor uploader extensions via reflection',
                ['error' => $e->getMessage()]
            );
        }
    }
}
