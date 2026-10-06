<?php

namespace TrialShield;

final class Fingerprint
{
    private string $secret;

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    public function create(array $browser = []): array
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $browserName = $this->detectBrowser($userAgent);
        $osName      = $this->detectOS($userAgent);

        $screen   = $this->clean($browser['screen'] ?? '');
        $language = $this->clean($browser['language'] ?? '');
        $timezone = $this->clean($browser['timezone'] ?? '');

        $deviceParts = [
            'browser'  => strtolower($browserName),
            'os'       => strtolower($osName),
            'screen'   => strtolower($screen),
            'language' => strtolower($language),
            'timezone' => strtolower($timezone),
        ];

        $deviceString = implode('|', $deviceParts);

        return [
            'ip_hash'          => $this->hash($ip),
            'fingerprint_hash' => $this->hash($deviceString),
            'browser'          => $browserName,
            'os'               => $osName,
            'screen'           => $screen,
            'language'         => $language,
            'timezone'         => $timezone,
        ];
    }

    public function hash(string $value): string
    {
        return hash_hmac('sha256', $value, $this->secret);
    }

    private function clean(string $value): string
    {
        return mb_substr(trim($value), 0, 100);
    }

    private function detectBrowser(string $ua): string
    {
        return match (true) {
            stripos($ua, 'Edg/') !== false    => 'Edge',
            stripos($ua, 'Chrome/') !== false => 'Chrome',
            stripos($ua, 'Firefox/') !== false => 'Firefox',
            stripos($ua, 'Safari/') !== false => 'Safari',
            stripos($ua, 'OPR/') !== false   => 'Opera',
            default                           => 'Other',
        };
    }

    private function detectOS(string $ua): string
    {
        return match (true) {
            stripos($ua, 'Windows') !== false => 'Windows',
            stripos($ua, 'Mac OS') !== false  => 'macOS',
            stripos($ua, 'Android') !== false => 'Android',
            stripos($ua, 'iPhone') !== false  => 'iOS',
            stripos($ua, 'iPad') !== false    => 'iPadOS',
            stripos($ua, 'Linux') !== false   => 'Linux',
            default                           => 'Other',
        };
    }
}