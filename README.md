# Kamain ApiJWTBundle

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
        request_matcher: KimaiPlugin\ApiJwtBundle\Authenticator\ApiRequestMatcher
        user_checker: App\Security\UserChecker
        custom_authenticators:
          - KimaiPlugin\ApiJwtBundle\Authenticator\TokenAuthenticatorBearer
      #...
```
