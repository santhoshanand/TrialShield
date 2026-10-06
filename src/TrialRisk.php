<?php

namespace TrialShield;

use PDO;

final class TrialRisk
{
    public function __construct(
        private PDO $db,
        private array $config
    ) {}

    public function check(array $signals): RiskResult
    {
        $score = 0;
        $reasons = [];
        $weights = $this->config['weights'];

        // 1. Existing device check
        if ($this->fingerprintUsedBefore($signals['fingerprint_hash'])) {
            $score += $weights['previous_device'] ?? 40;
            $reasons[] = 'previous_device';
        }

        // 2. IP History check
        $ipCount = $this->recentIpCount($signals['ip_hash'], $this->config['windows']['ip_history_minutes'] ?? 30);
        if ($ipCount >= 3) {
            $score += $weights['multiple_ip_trials'] ?? 30;
            $reasons[] = 'multiple_trials_same_ip';
        } elseif ($ipCount >= 1) {
            $score += $weights['previous_ip'] ?? 15;
            $reasons[] = 'previous_trial_same_ip';
        }

        // 3. Signup Velocity check
        $velocity = $this->recentIpCount($signals['ip_hash'], $this->config['windows']['velocity_minutes'] ?? 10);
        if ($velocity >= 3) {
            $score += $weights['signup_velocity'] ?? 25;
            $reasons[] = 'high_signup_velocity';
        }

        // 4. Payment Fingerprint check
        if (!empty($signals['payment_fingerprint']) && $this->paymentUsedBefore($signals['payment_fingerprint'])) {
            $score += $weights['previous_payment'] ?? 60;
            $reasons[] = 'previous_payment';
        }

        // 5. Active Block lists
        if ($this->isBlocked('fingerprint', $signals['fingerprint_hash'])) {
            $score += $weights['blocked_device'] ?? 100;
            $reasons[] = 'blocked_device';
        }

        if ($this->isBlocked('ip', $signals['ip_hash'])) {
            $score += $weights['blocked_ip'] ?? 80;
            $reasons[] = 'blocked_ip';
        }

        $level = $this->determineLevel($score);

        return new RiskResult($score, $level, $reasons, $this->config);
    }

    private function determineLevel(int $score): string
    {
        $t = $this->config['thresholds'];
        return match (true) {
            $score >= ($t['very_high'] ?? 100) => 'very_high',
            $score >= ($t['high']      ?? 60)  => 'high',
            $score >= ($t['medium']    ?? 30)  => 'medium',
            default                            => 'low',
        };
    }

    private function fingerprintUsedBefore(string $hash): bool
    {
        $stmt = $this->db->prepare("SELECT 1 FROM trial_signals WHERE fingerprint_hash = ? LIMIT 1");
        $stmt->execute([$hash]);
        return (bool) $stmt->fetchColumn();
    }

    private function paymentUsedBefore(string $hash): bool
    {
        $stmt = $this->db->prepare("SELECT 1 FROM trial_signals WHERE payment_fingerprint = ? LIMIT 1");
        $stmt->execute([$hash]);
        return (bool) $stmt->fetchColumn();
    }

    private function recentIpCount(string $ipHash, int $minutes): int
    {
        $minutes = max(1, min(1440, $minutes));
        $stmt = $this->db->prepare("
            SELECT COUNT(*) FROM trial_signals 
            WHERE ip_hash = ? AND created_at >= DATE_SUB(NOW(), INTERVAL {$minutes} MINUTE)
        ");
        $stmt->execute([$ipHash]);
        return (int) $stmt->fetchColumn();
    }

    private function isBlocked(string $type, string $hash): bool
    {
        $stmt = $this->db->prepare("
            SELECT 1 FROM trial_blocks 
            WHERE type = ? AND value_hash = ? AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1
        ");
        $stmt->execute([$type, $hash]);
        return (bool) $stmt->fetchColumn();
    }

    public function record(array $signals, int $userId, RiskResult $result): void
    {
        $stmt = $this->db->prepare("
            INSERT INTO trial_signals (
                user_id, fingerprint_hash, ip_hash, browser, os, screen, language, timezone, payment_fingerprint, risk_score, risk_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");

        $stmt->execute([
            $userId,
            $signals['fingerprint_hash'],
            $signals['ip_hash'],
            $signals['browser'] ?? null,
            $signals['os'] ?? null,
            $signals['screen'] ?? null,
            $signals['language'] ?? null,
            $signals['timezone'] ?? null,
            $signals['payment_fingerprint'] ?? null,
            $result->score(),
            $result->level()
        ]);
    }
}