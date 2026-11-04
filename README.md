# Aregowe_PolyShellProtection

## Purpose

Comprehensive defense-in-depth module that closes the **PolyShell** unrestricted file upload vulnerability (APSB25-94) in Adobe Commerce. PolyShell affects all Magento Open Source and Adobe Commerce versions up to 2.4.9-alpha2. No official isolated patch exists for production versions.

This module was originally forked from [markshust/magento2-module-polyshell-patch](https://github.com/markshust/magento-polyshell-patch) by [Mark Shust](https://github.com/markshust). With Mark's permission, his module's logic has been fully integrated into this one, and he has deprecated his package in favor of this module.

**Reference:** [Sansec — PolyShell: unrestricted file upload in Magento and Adobe Commerce](https://sansec.io/research/magento-polyshell)

If this module helped protect your store, consider [buying me a coffee ☕](https://ko-fi.com/aregowe) — it helps me keep maintaining and improving it.

## Installation

### Via Composer (recommended)

```bash
composer require aregowe/magento2-module-polyshell-protection
bin/magento module:enable Aregowe_PolyShellProtection
bin/magento setup:upgrade
bin/magento cache:flush
```

### Manually

Copy the module into your project:

```bash
mkdir -p app/code/Aregowe/PolyShellProtection
cp -r * app/code/Aregowe/PolyShellProtection/
bin/magento module:enable Aregowe_PolyShellProtection
bin/magento setup:upgrade
bin/magento cache:flush
```

### Uninstallation

```bash
bin/magento module:disable Aregowe_PolyShellProtection
bin/magento setup:upgrade
composer remove aregowe/magento2-module-polyshell-protection
bin/magento cache:flush
```

## Migrating from MarkShust_PolyshellPatch

This module **integrates and supersedes** [markshust/magento2-module-polyshell-patch](https://github.com/markshust/magento-polyshell-patch). You do **not** need both modules — this one includes all of Mark Shust's original protection and extends it significantly.

Mark Shust's module provided a focused two-plugin fix that enforced a 4-extension image allowlist (`jpg`, `jpeg`, `gif`, `png`) on `ImageContentValidator` and `ImageProcessor`. That logic is now fully integrated into this module's `HardenImageContentValidatorPlugin` and `HardenImageProcessorPlugin`, which add:
- Polyglot file scanning (detects valid images with embedded PHP)
- No-extension and double-extension attack detection
- Multi-pass URL decoding and obfuscation normalization
- Known attack filename/pattern matching
- Request path blocking at the FrontController and `pub/get.php` level
- Controller-level upload blocking for customer attribute and file upload endpoints
- Configurable filename validation for custom option file uploads via the Webapi File Processor, with admin-configurable allowed and blocked extension lists

The `composer.json` includes a `"replace"` directive for `markshust/magento2-module-polyshell-patch`, so Composer will automatically handle the transition.

### If you currently have MarkShust_PolyshellPatch installed

```bash
bin/magento module:disable MarkShust_PolyshellPatch
bin/magento setup:upgrade
composer require aregowe/magento2-module-polyshell-protection
bin/magento module:enable Aregowe_PolyShellProtection
bin/magento setup:upgrade
bin/magento cache:flush
```

Composer's `replace` directive will remove MarkShust's package automatically when this module is installed.

### Credits

This module was forked from [markshust/magento2-module-polyshell-patch](https://github.com/markshust/magento-polyshell-patch), created by [Mark Shust](https://github.com/markshust) and sponsored by [M.academy](https://m.academy/). Mark gave his permission to integrate his module's logic into this one and has deprecated his package in favor of this project. Thank you, Mark!

## Vulnerability Summary

Magento's REST API accepts file uploads as part of cart item custom options. When a product option has type **file**, Magento processes an embedded `file_info` object containing base64-encoded file data, a MIME type, and a filename. The file is written to `pub/media/custom_options/quote/` on the server.

Three critical checks are missing from core Magento:

1. **No option ID validation** — the submitted option ID is never verified against the product's actual options.
2. **No option type gating** — file upload logic triggers regardless of whether the product has a file-type option.
3. **No file extension restriction** — extensions like `.php`, `.phtml`, and `.phar` are not blocked. The only validation is `getimagesizefromstring`, which is trivially bypassed using polyglot files (valid image headers containing embedded PHP).

The most dangerous endpoints are the anonymous guest cart routes:

| Method | Endpoint | Auth Required |
|--------|----------|---------------|
| POST | `/V1/guest-carts/:cartId/items` | None |
| PUT | `/V1/guest-carts/:cartId/items/:itemId` | None |

### Live Attack Patterns

Attackers upload **polyglot files** — valid GIF or PNG images containing executable PHP. Two payload types are in active use:

- **Cookie-authenticated webshell** — GIF89a polyglot dropped as `index.php`, verifies cookie against hardcoded MD5 hash, executes arbitrary code via `eval(base64_decode())`.
- **Password-protected RCE shell** — uses `hash_equals()` with double-MD5 hash, passes commands to `system()`.

Common attack filenames: `index.php`, `780index.php` (option_id prefix), `json-shell.php`, `bypass.phtml`, `rce.php`, `shell.php`, `accesson.php`, `test.php`, `ato_poc.html`.

Post-exploitation deploys `accesson.php` backdoors across writable directories (`app/assets/images/`, `var/assets/images/`, `vendor/assets/images/`, etc.) and injects JavaScript malware loaders into CMS content.

## How This Module Protects

This module implements **eight layered Magento plugins** and **three security models** that block the attack at every interception point. If one layer is bypassed, subsequent layers catch it.

### Defense Layers (in execution order)

#### Layer 1 — Request Path Blocking

| Plugin | Target Class | Strategy |
|--------|-------------|----------|
| `BlockSuspiciousMediaPathPlugin` | `FrontController` | Blocks HTTP requests to `/media/customer_address/`, `/media/custom_options/`, etc. via `aroundDispatch`. Returns 404. |
| `BlockSuspiciousMediaAppPathPlugin` | `Media` (get.php) | Blocks media serving via the `pub/get.php` entrypoint for the same paths. Uses reflection to read `Media::$relativeFileName`. Returns 404. |

#### Layer 2 — Controller-Level Upload Blocking

| Plugin | Target Class | Strategy |
|--------|-------------|----------|
| `BlockCustomerAttributeFileUploadControllerPlugin` | `AbstractUploadFile` | Blocks ALL customer attribute file upload controllers at the entry point. Returns JSON error. |
| `BlockCustomerFileUploadPlugin` | `FileProcessor` | Blocks `saveTemporaryFile` and `moveTemporaryFile` for `customer_address`, `customer_addresses`, and `custom_options` entity types. Fails closed if reflection cannot read entity type. |

#### Layer 3 — Custom Option Upload Validation

| Plugin | Target Class | Strategy |
|--------|-------------|----------|
| `ValidateUploadedFileNamePlugin` | `File\Processor` (Webapi) | Validates the filename of custom option file uploads against the merged allowlist/blocklist via `FileUploadGuard::assertSafeFileName()`. Safe files pass through; dangerous files are blocked with a logged warning. |
| `ValidateUploadedFileContentPlugin` | `File\Processor` (Webapi) | Validates filename safety (extension, pattern, obfuscation) and scans file content for polyglot/embedded PHP. |
| `ValidateCustomOptionUploadPlugin` | `CustomOptionProcessor` | Validates filenames in custom option `file_info` payloads at cart/quote level via `FileUploadGuard::assertSafeFileName()`. Iterates all custom options; cart items without file payloads pass through unmodified. |

#### Layer 4 — Framework-Level Image Hardening

| Plugin | Target Class | Strategy |
|--------|-------------|----------|
| `HardenImageContentValidatorPlugin` | `ImageContentValidator` | After core validation, enforces a strict image-only extension allowlist, infers extensions for extension-less uploads by delegating to `FileUploadGuard::inferExtensionForFileName()` (MIME type is fetched lazily only when needed), blocks uploads when the MIME type is missing or unmapped, detects double-extension attacks (`.php.jpg`), scans base64 content for polyglot payloads. Integrates MarkShust_PolyshellPatch's extension check. |
| `HardenImageProcessorPlugin` | `ImageProcessor` | Before file write, locks the Uploader's allowed extensions via reflection, infers extensions for extension-less payloads by delegating to `FileUploadGuard::inferExtensionForFileName()` (MIME type is fetched lazily only when needed), blocks uploads with missing or unmapped MIME types and non-image extensions, scans for polyglot content. |

### Security Models

| Model | Responsibility |
|-------|---------------|
| `FileUploadGuard` | Orchestrates filename validation: configurable extension allowlist/blocklist (base code-defined sets merged with admin-configured additions via `getAllowedExtensions()` / `getBlockedExtensions()`), blocked-extension pattern matching, private multi-pass normalization (unicode decoding, URL decoding, CR/LF/TAB replacement, whitespace collapse), MIME-to-extension inference via `inferExtensionFromMimeType()`, and a combined infer-validate-normalize flow via `inferExtensionForFileName()` used by both image-hardening plugins. The blocklist always overrides all allowlists. Delegates attack-pattern and polyglot detection to AttackPatternDetector and PolyglotFileDetector. |
| `AttackPatternDetector` | Maintains a list of known attack filenames and regex patterns observed in active PolyShell campaigns. Blocks exact filename matches and suspicious patterns (option_id + index.php, double extensions, shell/backdoor naming, obfuscation hints). |
| `PolyglotFileDetector` | Detects polyglot files by checking if content starts with an image signature (PNG, GIF, JPEG, RIFF, ICO, CUR, BMP) and then scanning for embedded PHP code patterns (`<?php`, `eval(`, `system(`, `exec(`, etc.) and known attack beacon signatures (`409723*20`, campaign-specific MD5 hashes). |
| `SecurityPathGuard` | Evaluates request paths and media-relative paths against blocked directory prefixes (`/media/customer_address`, `/media/custom_options`, etc.). |
| `SecurityLogSanitizer` | Sanitizes log context values — strips control characters, collapses whitespace, enforces maximum length — to prevent log injection attacks. |

### Additional Defenses

- **Nginx deny rules** — recommended in tandem with this module to block direct access to `pub/media/custom_options/` at the web server level.

## Admin Configuration

The module provides an admin panel at **Stores > Configuration > PolyShell Protection** for configuring file upload extension policies without code changes.

### File Upload Settings

| Setting | Description |
|---------|-------------|
| **Base Allowed Extensions (read-only note)** | Displays the code-defined base allowlist: `7z, bmp, csv, doc, docx, gif, heic, jpeg, jpg, ods, odt, pdf, png, rar, rtf, txt, webp, xls, xlsx, zip`. |
| **Additional Allowed Extensions** | Comma-separated list of extra extensions to allow (e.g. `ai, psd, svg`). Case-insensitive. Extensions that match blocked patterns are always rejected regardless of this setting. |
| **Base Blocked Extensions (read-only note)** | Displays the code-defined base blocklist: `asp, aspx, bat, cgi, cmd, com, dll, exe, inc, jar, js, jsp, mjs, module, msi, phar, php (incl. php3–php8), phps, pht, phtml, phtm, pl, ps1, py, sh, shtml, so, vbs`. Double-extension patterns (e.g. `file.php.jpg`) are also blocked automatically. |
| **Additional Blocked Extensions** | Comma-separated list of extra extensions to block (e.g. `svg, swf, html`). Case-insensitive. **Overrides all allowlists** — if an extension appears here and in the allowed list, it will be blocked. |

### Precedence Rules

1. The **blocklist always wins**. If an extension appears in both the allowed and blocked lists, it is blocked.
2. Admin-configured extensions are merged with base code-defined sets at runtime.
3. Extensions matching `BLOCKED_EXTENSION_PATTERN` (executable/script patterns and double-extension attacks) are **always** rejected, even if added to the allowed list via admin.

### ACL

Access to the configuration section requires the `Aregowe_PolyShellProtection::config` ACL resource, nested under **Stores > Settings > Configuration**.

## Module Structure

```
app/code/Aregowe/PolyShellProtection/
├── etc/
│   ├── module.xml                     # Module declaration
│   ├── di.xml                         # Plugin wiring and DI configuration
│   ├── acl.xml                        # ACL resource for admin config access
│   ├── config.xml                     # Default configuration values
│   └── adminhtml/
│       └── system.xml                 # Admin UI: Stores > Config > PolyShell Protection
├── Logger/
│   ├── Logger.php                     # Dedicated Monolog logger channel
│   └── Handler/
│       └── SecurityHandler.php        # Writes to var/log/polyshell_security.log
├── Model/
│   ├── AttackPatternDetector.php      # Known attack filenames and regex patterns
│   ├── FileUploadGuard.php            # Orchestrator: extension, pattern, content checks
│   ├── PolyglotFileDetector.php       # Image signature + embedded PHP detection
│   ├── SecurityLogSanitizer.php       # Log context sanitization
│   └── SecurityPathGuard.php          # Request path blocking rules
├── Plugin/
│   ├── BlockCustomerAttributeFileUploadControllerPlugin.php
│   ├── BlockCustomerFileUploadPlugin.php
│   ├── BlockSuspiciousMediaAppPathPlugin.php
│   ├── BlockSuspiciousMediaPathPlugin.php
│   ├── HardenImageContentValidatorPlugin.php
│   ├── HardenImageProcessorPlugin.php
│   ├── ValidateCustomOptionUploadPlugin.php
│   ├── ValidateUploadedFileContentPlugin.php
│   └── ValidateUploadedFileNamePlugin.php
├── Test/Unit/
│   ├── MimeExtensionInferenceValidationTest.php
│   ├── Model/
│   │   ├── AttackPatternDetectorTest.php
│   │   ├── FileUploadGuardTest.php
│   │   ├── PolyglotFileDetectorTest.php
│   │   ├── SecurityLogSanitizerTest.php
│   │   └── SecurityPathGuardTest.php
│   └── Plugin/
│       ├── BlockCustomerAttributeFileUploadControllerPluginTest.php
│       ├── BlockCustomerFileUploadPluginTest.php
│       ├── BlockSuspiciousMediaAppPathPluginTest.php
│       ├── BlockSuspiciousMediaPathPluginTest.php
│       ├── HardenImageContentValidatorPluginTest.php
│       ├── HardenImageProcessorPluginTest.php
│       ├── ValidateCustomOptionUploadPluginTest.php
│       ├── ValidateUploadedFileContentPluginTest.php
│       └── ValidateUploadedFileNamePluginTest.php
└── registration.php
```

## Logging

All security events are written to `var/log/polyshell_security.log` via a dedicated Monolog channel (`polyshell_security`). Log entries include:

- Blocked upload attempts with sanitized filenames, entity types, and MIME types.
- Blocked request paths with client IP addresses.
- Blocked media serving attempts.
- Polyglot content detection events.
- Reflection failures that could degrade plugin effectiveness.

Log context values are sanitized by `SecurityLogSanitizer` to prevent log injection (control characters stripped, whitespace normalized, values truncated to 256 characters).

## Fail-Open vs Fail-Closed Design

| Plugin | Failure Mode | Rationale |
|--------|-------------|-----------|
| `BlockCustomerFileUploadPlugin` | **Fail-closed** | If reflection cannot read `entityTypeCode`, the entity type is set to `unknown_blocked` and the upload is rejected. Overly restrictive is safer than permissive. |
| `BlockSuspiciousMediaAppPathPlugin` | **Fail-open** | If reflection on `Media::$relativeFileName` fails, the request passes through. Fail-closed would break ALL media serving. Other layers (nginx, `BlockSuspiciousMediaPathPlugin`) provide backup. Reflection failures are logged at error level. |
| `HardenImageProcessorPlugin` (uploader lock) | **Fail-open** | If the uploader reflection fails, other layers (ImageContentValidator plugin, path blocking) still enforce extension restrictions. Failure is logged. |

## Compatibility

- **Adobe Commerce**: 2.4.8-p4 (tested), expected compatible with 2.4.7+
- **Not installable on 2.4.9 and newer** (`magento/framework` >= 103.0.9). Adobe fixed PolyShell in core 2.4.9: `CustomOptionProcessor` only processes `file_info` for options that really are of type `file`, and `ImageContentProcessor` rejects protected extensions. Composer will refuse to install this module on those versions; remove it when upgrading.
- **PHP**: 8.4 (tested). All reflection uses `::class` to access properties declared on parent classes correctly in PHP 8.4's stricter reflection model.
- **MarkShust_PolyshellPatch**: Integrates and replaces. The `composer.json` `replace` directive handles automatic migration.
- **Hyva Theme**: No frontend dependencies. This module operates entirely on backend API and framework interception points.

## Running Tests

```bash
# From Docker environment
docker compose exec phpfpm php vendor/bin/phpunit app/code/Aregowe/PolyShellProtection/Test/Unit/
```

## Verification After Deployment

1. **Check logs**: `tail -f var/log/polyshell_security.log` — should show blocked attempts during testing.
2. **Test blocked upload**: Use curl to attempt uploading a `.php` file via the guest cart API. Expect rejection.
3. **Test blocked paths**: Request `/media/custom_options/quote/test.php` directly. Expect 404.
4. **Test legitimate uploads**: Verify product image uploads via admin still work normally.
5. **Scan for existing compromise**: `find pub/media/custom_options -name '*.php' -o -name '*.phtml'` should return no results. Also check: `find . -name 'accesson.php' -type f`.

## Support

If this module saved your store, consider [buying me a coffee ☕ on Ko-fi](https://ko-fi.com/aregowe). Every tip is appreciated and helps fund continued security research and maintenance.
