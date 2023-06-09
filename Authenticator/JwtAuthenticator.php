<?php

namespace KimaiPlugin\ApiJwtBundle\Authenticator;

use App\Saml\SamlLoginAttributes;
use App\Saml\SamlProvider;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class JwtAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private SamlProvider $samlProvider,
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
        /**
         * :TODO add jwt validation!!
         */
        $jwt = $this->getJwtDecoded($request);
        $email = $jwt['email'];

        if (!$email) {
            throw new BadCredentialsException('Invalid JWT Token');
        }

        $userLoader = function ($email) use ($jwt) {

            $attributes = [
                "Email"     => [$email],
                "FirstName" => [$jwt['given_name'] ?? $email],
                "LastName"  => [$jwt['family_name'] ?? '***'],
            ];
            $loginAttributes = new SamlLoginAttributes();
            $loginAttributes->setAttributes($attributes);
            $loginAttributes->setUserIdentifier($email);

            try {
                $user = $this->samlProvider->findUser($loginAttributes);
            } catch (\Exception $e) {
                throw new \Exception("userLoader.samlProvider.Exception".$e->getMessage());
            }

            return $user;
        };

        return new SelfValidatingPassport(new UserBadge($email, $userLoader));
    }

    private function getJwtDecoded(Request $request): array|false
    {
        $auth = $request->headers->get('Authorization');
        if (!preg_match('/Bearer (.*)/', $auth, $found)) {
            throw new CustomUserMessageAuthenticationException('Invalid Bearer');
        }

        $bearer = $found[1];

        return json_decode(base64_decode(str_replace('_', '/', str_replace('-', '+', explode('.', $bearer)[1]))), true);
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
