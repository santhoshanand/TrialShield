<?php

use TrialShield\Fingerprint;
use TrialShield\TrialRisk;

require_once __DIR__ . '/../src/Fingerprint.php';
require_once __DIR__ . '/../src/RiskResult.php';
require_once __DIR__ . '/../src/TrialRisk.php';

$config = require_once __DIR__ . '/../config/config.example.php';

// Assume $pdo is already connected via PDO
// $pdo = new PDO(...);

// 1. Gather browser fields sent via hidden form inputs
$browserSignals = [
    'screen'   => $_POST['screen'] ?? '',
    'language' => $_POST['language'] ?? '',
    'timezone' => $_POST['timezone'] ?? ''
];

$fingerprintService = new Fingerprint($config['secret']);
$signals = $fingerprintService->create($browserSignals);

$signals['payment_fingerprint'] = $_POST['payment_fingerprint'] ?? null;

// 2. Evaluate risk
$riskEngine = new TrialRisk($pdo, $config);
$result = $riskEngine->check($signals);

// 3. Enforce policy based on result
if ($result->isBlocked()) {
    http_response_code(403);
    exit('Trial registration unavailable.');
}

if ($result->requiresPayment()) {
    // Flag account to require card verification upfront
    $requirePaymentMethod = true;
}

// 4. Create your user account
$userId = 12345; // Your user creation logic here

// 5. Record decision telemetry
$riskEngine->record($signals, $userId, $result);

echo "Trial started successfully. Risk Score: " . $result->score();