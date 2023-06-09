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
