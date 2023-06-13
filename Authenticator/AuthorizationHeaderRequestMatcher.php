<?php

namespace KimaiPlugin\ApiJwtBundle\Authenticator;

use App\API\Authentication\SessionAuthenticator;
use App\API\Authentication\TokenAuthenticator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;

final class AuthorizationHeaderRequestMatcher implements RequestMatcherInterface
{
    public function matches(Request $request): bool
    {
        return $request->headers->get('Accept') === 'application/json' &&
               $request->headers->has('Authorization');
    }
}
