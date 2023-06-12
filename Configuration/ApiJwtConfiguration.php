<?php

namespace KimaiPlugin\ApiJwtBundle\Configuration;

use App\Configuration\SystemConfiguration;

final class ApiJwtConfiguration
{
    public function __construct(private SystemConfiguration $configuration)
    {
    }

    public function getPublicKey(): string
    {
        $e = $this->configuration->find('api_jwt.public_key');

        if (\is_string($e)) {
            return $e;
        }

        return '';
    }
}
