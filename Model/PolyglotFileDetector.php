<?php

declare(strict_types=1);

namespace Aregowe\PolyShellProtection\Model;

use Magento\Framework\Exception\InputException;

class PolyglotFileDetector
{
    /**
     * Magic bytes (file signatures) for legitimate image formats.
     * Maps signature to format description.
     *
     * @var array<string, string>
     */
    private const IMAGE_SIGNATURES = [
        "\x89PNG\r\n\x1a\n" => 'PNG',
        "GIF87a" => 'GIF87a',
        "GIF89a" => 'GIF89a',
        "\xFF\xD8\xFF" => 'JPEG',
        "RIFF" => 'RIFF/WAVE/AVI',
        "\x00\x00\x01\x00" => 'ICO',
        "\x00\x00\x02\x00" => 'CUR',
        "BM" => 'BMP',
    ];

    /**
     * Dangerous PHP patterns that indicate code injection in image files.
     *
     * @var array<string>
     */
    private const PHP_CODE_PATTERNS = [
        '<?php',
        '<?=',
        'eval(',
        'base64_decode',
        'system(',
        'exec(',
        'passthru(',
        'shell_exec(',
        'proc_open(',
        'popen(',
        'fsockopen(',
        'socket_create(',
        'fopen(',
        '@copy',
        '$_FILES',
        '$_REQUEST',
        '$_COOKIE',
        '$_POST',
        'md5_file',
        'hash_equals',
        'ob_start',
        'ob_get_clean',
        'strip_tags',
        'preg_replace',
        '/e"',  // Deprecated /e modifier
    ];

    /**
     * Known beacon/signature patterns from active PolyShell campaigns.
     *
     * @var array<string>
     */
    private const ATTACK_SIGNATURES = [
        '409723*20',           // Common beacon in PolyShell payloads
        '8194460',             // Result of 409723*20; used as fingerprint
        'a17028468cb2a870d460676d6d6da3ad63706778e3',  // Cookie auth hash (first variant)
        '4009d3fa8132195a2dab4dfa3affc8d2',            // Double-MD5 hash (second variant)
        '17028f487cb2a84607646da3ad3878ec',            // accesson.php variant hash
    ];

    /**
     * Detect polyglot files: images with embedded PHP code.
     *
     * @param resource|string $fileContent Raw file content or readable stream
     * @param string|null $filename For context in error messages
     * @throws InputException
     */
    public function assertNotPolyglot($fileContent, ?string $filename = null): void
    {
        // Limit stream reads to 100 MB to prevent memory exhaustion on oversized payloads.
        $binary = is_resource($fileContent)
            ? stream_get_contents($fileContent, 100 * 1024 * 1024)
            : $fileContent;

        if (!is_string($binary) || strlen($binary) === 0) {
            throw new InputException(__('Failed to read uploaded file content for security validation.'));
        }

        // Check if file starts with image signature
        $isImageFile = $this->startsWithImageSignature($binary);
        if (!$isImageFile) {
            // Not an image, proceed with other checks
            return;
        }

        // File is (or claims to be) an image. Scan for embedded PHP code.
        $this->assertNoEmbeddedCode($binary, $filename);
    }

    /**
     * Check if binary content starts with known image file signature.
     * This is intentionally permissive (to catch polyglots) but returns early
     * if not an image at all.
     *
     * @param string $binary
     * @return bool
     */
    private function startsWithImageSignature(string $binary): bool
    {
        foreach (self::IMAGE_SIGNATURES as $signature => $_format) {
            if (str_starts_with($binary, $signature)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Scan file content for dangerous PHP patterns and attack signatures.
     *
     * @param string $binary
     * @param string|null $filename
     * @throws InputException
     */
    private function assertNoEmbeddedCode(string $binary, ?string $filename): void
    {
        $content = $binary;

        // Convert binary to searchable format (handle null bytes gracefully)
        $contentSearchable = str_replace("\x00", '', $content);

        // Check for PHP code markers
        foreach (self::PHP_CODE_PATTERNS as $pattern) {
            if (stripos($contentSearchable, $pattern) !== false) {
                $contextFile = $filename ? sprintf(' in file %s', $filename) : '';
                throw new InputException(
                    __(
                        'Uploaded file contains executable code and is not permitted for security reasons%s',
                        $contextFile
                    )
                );
            }
        }

        // Check for known attack signatures
        foreach (self::ATTACK_SIGNATURES as $signature) {
            if (stripos($contentSearchable, $signature) !== false) {
                $contextFile = $filename ? sprintf(' in file %s', $filename) : '';
                throw new InputException(
                    __(
                        'Uploaded file matches known malicious payload signature%s',
                        $contextFile
                    )
                );
            }
        }
    }
}
