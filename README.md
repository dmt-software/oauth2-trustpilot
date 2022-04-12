# Trustpilot Provider for OAuth 2.0 Client

## Install

`composer require dmt-software/oauth2-trustpilot`

## Usage

```php
use DMT\OAuth2\Client\Provider\Trustpilot;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

$provider = new Trustpilot([
    'clientId' => '{ your_client_id }',
    'clientSecret' => '{ your_client_secret }',
]);

try {
    $accessToken = $provider->getAccessToken(
        'password', [
            'username' => '{ your_username }',
            'password' => '{ your_password }'
        ]
    );
} catch (IdentityProviderException $exception) {
    if ($exception->getCode() === 401) {
        // token is expired
    }
    if ($exception->getCode() === 429) {
        // too many requests
    }
}
```

> see more examples on [league/oauth2-client](https://oauth2-client.thephpleague.com/usage/)

## Error handling

Unfortunately the response body in case of an error is not consistent. To better understand the reason a request is 
failed call the `IdentityProviderException::getResponseBody` method.

