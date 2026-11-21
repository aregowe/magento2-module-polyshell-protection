<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Plugin;

use Magento\Framework\App\ResponseInterface;
use Magento\Framework\Exception\NotFoundException;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use Magento\MediaStorage\App\Media;
use Aregowe\PolyShellProtection\Logger\Logger;
use Aregowe\PolyShellProtection\Model\SecurityLogSanitizer;
use Aregowe\PolyShellProtection\Model\SecurityPathGuard;

class BlockSuspiciousMediaAppPathPlugin
{
    private Logger $logger;

    private RemoteAddress $remoteAddress;

    private SecurityPathGuard $securityPathGuard;

    private SecurityLogSanitizer $logSanitizer;

    private ?\ReflectionProperty $relativeFileNameProperty = null;

    public function __construct(
        Logger $logger,
        RemoteAddress $remoteAddress,
        SecurityPathGuard $securityPathGuard,
        SecurityLogSanitizer $logSanitizer
    ) {
        $this->logger = $logger;
        $this->remoteAddress = $remoteAddress;
        $this->securityPathGuard = $securityPathGuard;
        $this->logSanitizer = $logSanitizer;
    }

    /**
     * Block suspicious media paths served by get.php / Media app layer.
     *
     * NOTE: This plugin deliberately fails OPEN — if the relativeFileName property
     * cannot be read via reflection (e.g. renamed in a future Magento version),
     * requests pass through normally. Fail-closed here would break ALL media
     * serving. The nginx deny blocks and BlockSuspiciousMediaPathPlugin provide
     * additional layers that do not depend on reflection.
     *
     * @param Media $subject
     * @param callable $proceed
     * @return ResponseInterface
     * @throws NotFoundException
     */
    public function aroundLaunch(Media $subject, callable $proceed): ResponseInterface
    {
        $relativeFileName = $this->getRelativeFileName($subject);

        if ($relativeFileName !== '' && $this->securityPathGuard->isBlockedMediaRelativePath($relativeFileName)) {
            $this->logger->warning('PolyShell guard blocked media app request to suspicious path.', [
                'relative_path' => $this->logSanitizer->sanitizeString($relativeFileName),
                'ip' => $this->remoteAddress->getRemoteAddress(),
            ]);

            throw new NotFoundException(__('File not found.'));
        }

        return $proceed();
    }

    private function getRelativeFileName(Media $mediaApp): string
    {
        try {
            if ($this->relativeFileNameProperty === null) {
                $reflection = new \ReflectionClass(Media::class);
                if (!$reflection->hasProperty('relativeFileName')) {
                    return '';
                }
                $this->relativeFileNameProperty = $reflection->getProperty('relativeFileName');
            }

            $value = $this->relativeFileNameProperty->getValue($mediaApp);

            return is_string($value) ? trim($value) : '';
        } catch (\Throwable $exception) {
            $this->logger->error(
                'PolyShellProtection: Reflection on Media::relativeFileName failed. Media path blocking may be degraded.',
                ['error' => $exception->getMessage()]
            );
            return '';
        }
    }
}
