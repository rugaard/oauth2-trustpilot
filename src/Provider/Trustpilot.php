<?php
namespace Rugaard\OAuth2\Client\Trustpilot\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

/**
 * Class Trustpilot
 *
 * @package Rugaard\OAuth2\Client\Trustpilot\Provider
 */
class Trustpilot extends AbstractProvider
{
    /**
     * Returns the base URL for authorizing a client.
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return 'https://authenticate.trustpilot.com';
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * @param  array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return sprintf(
            'https://api.trustpilot.com/v1/oauth/oauth-business-users-for-applications/%s',
            array_key_exists('grant_type', $params) && $params['grant_type'] === 'refresh_token' ? 'refresh' : 'accesstoken'
        );
    }

    /**
     * Builds request options used for requesting an access token.
     *
     * @param  array $params
     * @return array
     */
    protected function getAccessTokenOptions(array $params)
    {
        // Generate token options.
        $options = parent::getAccessTokenOptions($params);

        // Add Authorization header to token options.
        $options['headers']['Authorization'] = base64_encode($params['client_id'] . ':' . $params['client_secret']);

        return $options;
    }

    /**
     * Checks a provider response for errors.
     *
     * @param  \Psr\Http\Message\ResponseInterface $response
     * @param  array|string                        $data
     * @return void
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() === 200) {
            return;
        }

        throw new IdentityProviderException(
            !empty($data['message']) ? $data['message'] : $response->getReasonPhrase(),
            $response->getStatusCode(),
            $data
        );
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param  \League\OAuth2\Client\Token\AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return 'https://api.trustpilot.com/v1/business-units/' . $token->getResourceOwnerId() . '/profileinfo';
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  \League\OAuth2\Client\Token\AccessToken $token
     * @return \League\OAuth2\Client\Provider\ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new GenericResourceOwner($response, $token->getResourceOwnerId());
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return [];
    }
}
