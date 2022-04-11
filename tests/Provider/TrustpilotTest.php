<?php

namespace DMT\Test\OAuth\Client\Provider;

use DMT\OAuth2\Client\Provider\Trustpilot;
use PHPUnit\Framework\TestCase;

class TrustpilotTest extends TestCase
{
    /**
     * This test could be used to test your credentials.
     *
     * It is only available when a config.ini file is present, containing:
     *  - clientId
     *  - clientSecret
     *  - username
     *  - password
     *
     * ~$ vendor/bin/phpunit --configuration phpunit.xml.dist --group integration tests
     *
     * Remove the config.ini afterwards.
     *
     * @group integration
     */
    public function testFetchAccessToken()
    {
        $configFile = __DIR__ . '/../../config.ini';

        if (!file_exists($configFile)) {
            $this->markTestIncomplete('No configuration found');
        }

        $config = parse_ini_file($configFile);

        $provider = new Trustpilot([
            'clientId' => $config['clientId'],
            'clientSecret' => $config['clientSecret'],
        ]);

        $accessToken = $provider->getAccessToken(
            'password', [
                'username' => $config['username'],
                'password' => $config['password']
            ]
        );

        $this->assertNotEmpty($accessToken->getToken());
        $this->assertNotEmpty($accessToken->getResourceOwnerId());
    }
}
