<?php

namespace KimaiPlugin\ApiJwtBundle\Authenticator;

use App\Saml\SamlLoginAttributes;
use App\Saml\SamlProvider;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class JwtAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private SamlProvider $samlProvider,
        private string $apijwtPublicKey,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        $json = $request->headers->get('Accept') === 'application/json';
        $auth = $request->headers->get('Authorization');

        return $json && $auth && str_contains($auth, 'Bearer');
    }

    public function authenticate(Request $request): Passport
    {
        $jwtToken = $this->getJwtToken($request);

        $keyParts = str_split($this->apijwtPublicKey, 64);
        array_unshift($keyParts, '-----BEGIN PUBLIC KEY-----');
        $keyParts[] = '-----END PUBLIC KEY-----';
        $keyfile = implode(PHP_EOL, $keyParts);

        $token = JWT::decode($jwtToken, new Key($keyfile, 'RS256'));

        $userLoader = function ($email) use ($token) {
            $attributes = [
                'Email' => [$email],
                'FirstName' => [$token->given_name ?? ''],
                'LastName' => [$token->family_name ?? ''],
            ];

            $loginAttributes = new SamlLoginAttributes();
            $loginAttributes->setAttributes($attributes);
            $loginAttributes->setUserIdentifier($token->preferred_username);

            try {
                $user = $this->samlProvider->findUser($loginAttributes);
            } catch (\Exception $e) {
                throw new \Exception('userLoader.samlProvider.Exception' . $e->getMessage());
            }

            return $user;
        };

        return new SelfValidatingPassport(new UserBadge($token->email, $userLoader));
    }

    public function is_jwt_valid($jwt, $secret = 'secret') {
        // split the jwt
        $tokenParts = explode('.', $jwt);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signature_provided = $tokenParts[2];

        // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
        $expiration = json_decode($payload)->exp;
        $is_token_expired = ($expiration - time()) < 0;

        // build a signature based on the header and payload using the secret
        $base64_url_header = base64url_encode($header);
        $base64_url_payload = base64url_encode($payload);
        $signature = hash_hmac('SHA256', $base64_url_header . '.' . $base64_url_payload, $secret);
        $base64_url_signature = base64url_encode($signature);

        // verify it matches the signature provided in the jwt
        $is_signature_valid = ($base64_url_signature === $signature_provided);

        throw new \Exception(json_encode([$signature, $signature_provided]));
        if ($is_token_expired || !$is_signature_valid) {
            return false;
        } else {
            return true;
        }
    }

    private function getJwtToken(Request $request): string
    {
        $auth = $request->headers->get('Authorization');
        if (!preg_match('/Bearer (.*)/', $auth, $found)) {
            throw new CustomUserMessageAuthenticationException('Invalid Bearer');
        }

        return $found[1];
    }

    private function getJwtDecoded(Request $request): array|false
    {
        $auth = $request->headers->get('Authorization');
        if (!preg_match('/Bearer (.*)/', $auth, $found)) {
            throw new CustomUserMessageAuthenticationException('Invalid Bearer');
        }

        $bearer = $this->getJwtToken($request);

        return json_decode(base64_decode(str_replace('_', '/', str_replace('-', '+', explode('.', $bearer)[1]))), true);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $data = [
            'message' => 'onAuthenticationFailure . ' . ($exception instanceof CustomUserMessageAuthenticationException ? $exception->getMessage() : 'Invalid credentials'),
        ];

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
    }
}

function base64url_encode($data)
{
    // First of all you should encode $data to Base64 string
    $b64 = base64_encode($data);

    // Make sure you get a valid result, otherwise, return FALSE, as the base64_encode() function do
    if ($b64 === false) {
        return false;
    }

    // Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
    $url = strtr($b64, '+/', '-_');

    // Remove padding character from the end of line and return the Base64URL result
    return rtrim($url, '=');
}
