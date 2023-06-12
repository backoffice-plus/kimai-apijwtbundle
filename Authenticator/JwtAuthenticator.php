<?php

namespace KimaiPlugin\ApiJwtBundle\Authenticator;

use App\Saml\SamlLoginAttributes;
use App\Saml\SamlProvider;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use KimaiPlugin\ApiJwtBundle\Configuration\ApiJwtConfiguration;
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
        private ApiJwtConfiguration $config,
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

        $keyParts = str_split($this->config->getPublicKey(), 64);
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
                throw new \Exception("userLoader.samlProvider.Exception".$e->getMessage());
            }

            return $user;
        };

        return new SelfValidatingPassport(new UserBadge($token->email, $userLoader));
    }

    private function getJwtToken(Request $request): string
    {
        $auth = $request->headers->get('Authorization');
        if (!preg_match('/Bearer (.*)/', $auth, $found)) {
            throw new CustomUserMessageAuthenticationException('Invalid Bearer');
        }

        return $found[1];
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $data = [
            'message' => 'onAuthenticationFailure . '.($exception instanceof CustomUserMessageAuthenticationException ? $exception->getMessage() : 'Invalid credentials'),
        ];

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
    }
}
