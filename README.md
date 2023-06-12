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

create api_jwt.yaml in config/packages and set public key
```yaml
api_jwt:
  public_key: '%env(KIMAI_APIJWT_PUBLIC_KEY)%'
```
```dotenv
KIMAI_APIJWT_PUBLIC_KEY=
```
