<?php

/*
 * This file is part of the Kimai time-tracking app.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace KimaiPlugin\ApiJwtBundle\Authenticator;

use App\API\Authentication\SessionAuthenticator;
use App\API\Authentication\TokenAuthenticator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;

final class ApiRequestMatcher implements RequestMatcherInterface
{
    public function matches(Request $request): bool
    {
        return $request->headers->get('Accept') === 'application/json' &&
               $request->headers->has('Authorization');
    }
}
