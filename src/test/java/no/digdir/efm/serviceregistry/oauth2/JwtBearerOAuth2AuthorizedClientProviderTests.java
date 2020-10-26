package no.digdir.efm.serviceregistry.oauth2;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.test.context.junit4.SpringRunner;

import java.time.Duration;
import java.time.Instant;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
public class JwtBearerOAuth2AuthorizedClientProviderTests {

    private JwtBearerOAuth2AuthorizedClientProvider target;

    private AuthorizationGrantType grantType = JwtBearerGrantRequest.JWT_BEARER_GRANT_TYPE;
    private ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("registration")
            .authorizationGrantType(grantType)
            .build();
    private TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "password");

    @Mock
    private OAuth2AccessTokenResponseClient<JwtBearerGrantRequest> tokenResponseClient;

    @Before
    public void setUp() {
        target = new JwtBearerOAuth2AuthorizedClientProvider(tokenResponseClient);
    }

    @Test(expected = IllegalArgumentException.class)
    public void authorize_ContextIsNull_ShouldThrow() {
        target.authorize(null);
    }

    @Test
    public void authorize_InvalidGrant_ShouldReturnNull() {
        AuthorizationGrantType grantType = new AuthorizationGrantType("not:jwt:bearer");
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("registration")
                .authorizationGrantType(grantType)
                .build();
        TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "password");
        OAuth2AuthorizationContext context = OAuth2AuthorizationContext.withClientRegistration(clientRegistration)
                .principal(principal)
                .build();

        assertNull(target.authorize(context));
    }

    @Test
    public void authorize_TokenIsNotExpired_ShouldReturnClient() {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "access-token", issuedAt, expiresAt);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration,
                principal.getName(), accessToken);
        OAuth2AuthorizationContext context = OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
                .principal(principal)
                .build();

        assertNotNull(target.authorize(context));
    }

    @Test
    public void authorize_TokenIsExpired_ShouldReauthorize() {
        Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
        Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "expired-access-token", issuedAt, expiresAt);
        OAuth2AccessTokenResponse tokenResponse = OAuth2AccessTokenResponse
                .withToken("token")
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .build();
        when(tokenResponseClient.getTokenResponse(any())).thenReturn(tokenResponse);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration,
                principal.getName(), accessToken);
        OAuth2AuthorizationContext context = OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
                .principal(principal)
                .build();

        OAuth2AuthorizedClient result = target.authorize(context);

        assertNotNull(result);
    }

    @Test
    public void authorize_TokenIsNotExpiredButClockSkewForcesExpiry_ShouldReauthorize() {
        Instant now = Instant.now();
        Instant issuedAt = now.minus(Duration.ofMinutes(60));
        Instant expiresAt = now.minus(Duration.ofMinutes(1));
        OAuth2AccessToken expiresInOneMinAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "soon-expired-access-token", issuedAt, expiresAt);
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration,
                principal.getName(), expiresInOneMinAccessToken);
        target.setClockSkew(Duration.ofSeconds(90));
        OAuth2AccessTokenResponse tokenResponse = OAuth2AccessTokenResponse
                .withToken("token")
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .build();
        when(tokenResponseClient.getTokenResponse(any())).thenReturn(tokenResponse);
        OAuth2AuthorizationContext context = OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
                .principal(principal)
                .build();

        assertNotNull(target.authorize(context));
    }
}
