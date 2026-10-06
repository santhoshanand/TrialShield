# TrialShield

Lightweight trial-abuse detection and risk scoring for PHP SaaS applications.

Detect suspicious repeat trials using:
* IP reputation history
* Browser and OS characteristics
* Screen resolution & hardware layout
* Locale and timezone matching
* Payment token fingerprints
* Signup velocity tracking

No framework. No external API. No tracking script dependencies. Pure PHP 8+ and PDO.

---

## Quick Start

```php
use TrialShield\Fingerprint;
use TrialShield\TrialRisk;

$config = require 'config/config.php';

$fingerprint = new Fingerprint($config['secret']);
$signals =$fingerprint->create([
    'screen'   => $_POST['screen'] ?? '',
    'language' => $_POST['language'] ?? '',
    'timezone' => $_POST['timezone'] ?? ''
]);

$risk = new TrialRisk($pdo, $config);$result = $risk->check($signals);

if ($result->isBlocked()) {
    // Reject trial signup
}

$userId = createUser();
$risk->record($signals, $userId,$result);

```

Requirements
PHP 8.0+

MySQL 5.7+ / MariaDB

PDO Extension

License
MIT License.
