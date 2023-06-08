<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace KimaiPlugin\ApiJwtBundle\Authenticator;

use App\Entity\User;
use App\Repository\ApiUserRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CustomCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class TokenAuthenticatorBearer extends AbstractAuthenticator
{
    public function __construct(private ApiUserRepository $userProvider, private PasswordHasherFactoryInterface $passwordHasherFactory)
    {
    }

    public function supports(Request $request): ?bool
    {
        $json = $request->headers->get('Accept') === 'application/json';
        $auth = $request->headers->get('Authorization');
        return $json && $auth && str_contains($auth,'Bearer');
    }

    public function authenticate(Request $request): Passport
    {
        $jwt = $this->getJwtDecoded($request);
        $email = $jwt['email'];

        if (!$email) {
            throw new BadCredentialsException('Invalid JWT Token');
        }

        return new SelfValidatingPassport(new UserBadge($email));
    }

    private function getJwtDecoded(Request $request): array|false
    {
        $auth = $request->headers->get('Authorization');
        if(!preg_match('/Bearer (.*)/', $auth, $found)) {
            throw new CustomUserMessageAuthenticationException('Invalid Bearer');
        }

        $bearer = $found[1];
        return json_decode(base64_decode(str_replace('_', '/', str_replace('-','+',explode('.', $bearer)[1]))), true);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $data = [
            'message' => $exception instanceof CustomUserMessageAuthenticationException ? $exception->getMessage() : 'Invalid credentials'
        ];

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
    }
}
