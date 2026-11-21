<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Test\Unit\Plugin;

trait ThrowsOnDeprecationTrait
{
    private function throwOnDeprecation(?string $staticCacheOwner = null, ?string $staticCacheProperty = null): void
    {
        if ($staticCacheOwner !== null) {
            (new \ReflectionProperty($staticCacheOwner, $staticCacheProperty))->setValue(null, null);
        }

        set_error_handler(
            static function (int $severity, string $message): never {
                throw new \Exception($message);
            },
            E_DEPRECATED | E_USER_DEPRECATED
        );
    }

    protected function tearDown(): void
    {
        restore_error_handler();
        parent::tearDown();
    }
}
