<?php

return [
    'secret' => 'change-me-to-a-long-random-secret-key',
    
    'weights' => [
        'previous_device'       => 40,
        'previous_ip'           => 15,
        'multiple_ip_trials'    => 30,
        'previous_payment'      => 60,
        'signup_velocity'       => 25,
        'blocked_device'        => 100,
        'blocked_ip'            => 80,
    ],

    'thresholds' => [
        'medium'    => 30,
        'high'      => 60,
        'very_high' => 100,
    ],

    'windows' => [
        'ip_history_minutes' => 30,
        'velocity_minutes'   => 10,
    ],
];