# Kamai ApiJWTBundle

## Installation

copy all files to ApiJWTBundle in var/plugins/
```
var/plugins/
├── ApiJWTBundle
|   └ ... copy all ...

```

add this to the firewalls part at security.yaml
```yaml
 security:
   firewalls:
     #...
     apiJwtBundle:
       request_matcher: KimaiPlugin\ApiJwtBundle\Authenticator\AuthorizationHeaderRequestMatcher
       user_checker: App\Security\UserChecker
       custom_authenticators:
         - KimaiPlugin\ApiJwtBundle\Authenticator\JwtAuthenticator
     #...
```

add this to the .env file
```dotenv
KIMAI_APIJWT_PUBLIC_KEY=
```
