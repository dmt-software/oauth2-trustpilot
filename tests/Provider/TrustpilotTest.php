<?php

namespace DMT\Test\OAuth\Client\Provider;

use DMT\OAuth2\Client\Provider\Trustpilot;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class TrustpilotTest extends TestCase
{
    /** @var string[] */
    private $credentials = [
        'clientId' => 'my-client-id',
        'clientSecret' => 'my-client-secret',
        'redirectUri' => 'my-redirect-uri',
    ];

    /** @var Trustpilot */
    private $provider;

    public function setUp(): void
    {
        $this->provider = new Trustpilot($this->credentials);
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl([]);

        $this->assertStringContainsString('trustpilot.com', parse_url($url, PHP_URL_HOST));
    }

    public function testGetBaseAuthorizationUrl()
    {
        $url = $this->provider->getBaseAuthorizationUrl();

        $this->assertStringContainsString('trustpilot.com', parse_url($url, PHP_URL_HOST));
    }

    public function testGetBaseAccessTokenUrl()
    {
        $url = $this->provider->getBaseAccessTokenUrl([]);

        $this->assertStringContainsString('trustpilot.com', parse_url($url, PHP_URL_HOST));
    }

    public function testGetResourceOwnerDetailsUrl()
    {
        $accessToken = new AccessToken([
            'access_token' => 'c91edc1ad4d069b117ed7dc7',
            'resource_owner_id' => '2d41b60214b2fc6f2e2647e8',
            'refresh_token' => '52f30f0e9bd8d74c8a7e7eb2',
            'expires_in' => "359999",
        ]);

        $url = $this->provider->getResourceOwnerDetailsUrl($accessToken);

        $this->assertStringContainsString($accessToken->getResourceOwnerId(), $url);
        $this->assertStringContainsString('trustpilot.com', parse_url($url, PHP_URL_HOST));
    }

    public function testGetAccessToken()
    {
        $response = new Response(200, ['Content-Type' => 'application/json']);
        $response->getBody()->write(file_get_contents(__DIR__ . '/../data/token.json'));

        $client = new Client([
            'handler' => HandlerStack::create(
                new MockHandler([$response])
            )
        ]);

        $this->provider->setHttpClient($client);

        $accessToken = $this->provider->getAccessToken(
            'password',
            [
                'username' => 'my-user',
                'password' => 'my-pass',
            ]
        );

        $this->assertFalse($accessToken->hasExpired());
        $this->assertNotEmpty($accessToken->getToken());
        $this->assertNotEmpty($accessToken->getRefreshToken());
        $this->assertNotEmpty($accessToken->getResourceOwnerId());
    }

    public function testRefreshAccessToken()
    {
        $accessToken = new AccessToken([
            'access_token' => '52f30f0e9bd8d74c8a7e7eb2',
            'resource_owner_id' => '2d41b60214b2fc6f2e2647e8',
            'refresh_token' => 'c91edc1ad4d069b117ed7dc7',
            'expires_in' => "359999",
        ]);

        $response = new Response(200, ['Content-Type' => 'application/json']);
        $response->getBody()->write(file_get_contents(__DIR__ . '/../data/token.json'));

        $client = new Client([
            'handler' => HandlerStack::create(
                new MockHandler([$response])
            )
        ]);

        $this->provider->setHttpClient($client);

        $accessToken = $this->provider->getAccessToken(
            'refresh_token',
            [
                'refresh_token' => $accessToken->getRefreshToken()
            ]
        );

        $this->assertFalse($accessToken->hasExpired());
        $this->assertNotEmpty($accessToken->getToken());
        $this->assertNotEmpty($accessToken->getRefreshToken());
        $this->assertNotEmpty($accessToken->getResourceOwnerId());
    }

    public function testGetResourceOwner()
    {
        $accessToken = new AccessToken([
            'access_token' => 'c91edc1ad4d069b117ed7dc7',
            'resource_owner_id' => '2d41b60214b2fc6f2e2647e8',
            'refresh_token' => '52f30f0e9bd8d74c8a7e7eb2',
            'expires_in' => "359999",
        ]);

        $response = new Response(200, ['Content-Type' => 'application/json']);
        $response->getBody()->write(file_get_contents(__DIR__ . '/../data/token.json'));

        $client = new Client([
            'handler' => HandlerStack::create(
                new MockHandler([
                    new Response(200, [], file_get_contents(__DIR__ . '/../data/token.json')),
                    $response
                ])
            )
        ]);

        $this->provider->setHttpClient($client);

        $resourceOwner = $this->provider->getResourceOwner($accessToken);

        $this->assertInstanceOf(ResourceOwnerInterface::class, $resourceOwner);
        $this->assertSame($accessToken->getResourceOwnerId(), $resourceOwner->getId());
    }

    /**
     * @dataProvider provideFailure
     *
     * @param ResponseInterface $response
     * @throws IdentityProviderException
     */
    public function testGetAccessTokenFailure(ResponseInterface $response)
    {
        $body = $response->getBody()->getContents();
        $data = $body ? json_decode($body, true) : [];

        $this->expectExceptionObject(
            new IdentityProviderException($response->getReasonPhrase(), $response->getStatusCode(), $data)
        );

        $client = new Client([
            'handler' => HandlerStack::create(
                new MockHandler([$response])
            )
        ]);

        $this->provider->setHttpClient($client);

        $this->provider->getAccessToken(
            'password',
            [
                'username' => 'my-user',
                'password' => 'my-pass',
            ]
        );
    }

    public function provideFailure()
    {
        return [
            [new Response(401, [], '{"reason": "Authentication Failed"}')],
            [new Response(429, ['Content-Type' => 'text/plain'])],
            [new Response(503, ['Content-Type' => 'text/plain'])],
        ];
    }

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
            'password',
            [
                'username' => $config['username'],
                'password' => $config['password']
            ]
        );

        $this->assertNotEmpty($accessToken->getToken());
        $this->assertNotEmpty($accessToken->getResourceOwnerId());
    }
}
