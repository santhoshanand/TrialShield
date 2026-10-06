<?php

namespace TrialShield;

final class RiskResult
{
    public function __construct(
        private int $score,
        private string $level,
        private array $reasons,
        private array $config
    ) {}

    public function score(): int
    {
        return $this->score;
    }

    public function level(): string
    {
        return $this->level;
    }

    public function reasons(): array
    {
        return $this->reasons;
    }

    public function isBlocked(): bool
    {
        $veryHighThreshold = $this->config['thresholds']['very_high'] ?? 100;
        return in_array('blocked_device', $this->reasons, true) ||
               in_array('blocked_ip', $this->reasons, true) ||
               $this->score >= $veryHighThreshold;
    }

    public function requiresPayment(): bool
    {
        $highThreshold = $this->config['thresholds']['high'] ?? 60;
        return $this->level === 'high' || $this->score >= $highThreshold;
    }
}