package no.digdir.efm.serviceregistry.oauth2;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.digdir.efm.serviceregistry.config.ClientConfigurationProperties;
import no.digdir.efm.serviceregistry.keystore.KeystoreAccessor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtBearerAccessTokenResponseClient implements OAuth2AccessTokenResponseClient<JwtBearerGrantRequest> {

    private static final long BLOCK_DURATION_IN_SECONDS = 30L;
    private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";
    private static final long EXPIRES_IN_SECONDS = 120L;

    private final ClientConfigurationProperties properties;
    @Qualifier("OidcProviderWebClient")
    private final WebClient webClient;
    private final KeystoreAccessor keystoreAccessor;
    private final JWSSigner jwsSigner;

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(JwtBearerGrantRequest authorizationGrantRequest) {
        Assert.notNull(authorizationGrantRequest, "authorizationGrantRequest cannot be null");
        OidcTokenResponse tokenResponse = fetchToken(makeJwt());
        String accessToken = tokenResponse.getAccessToken();
        log.debug("Received access token:\n{}", accessToken);
        Set<String> scope = Sets.newHashSet(
                !Strings.isNullOrEmpty(tokenResponse.getScope())
                        ? tokenResponse.getScope().split(" ")
                        : properties.getOidc().getScopes().split(","));
        return OAuth2AccessTokenResponse.withToken(accessToken)
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(tokenResponse.getExpiresIn())
                .scopes(scope)
                .build();
    }

    private String makeJwt() {
        try {
            List<Base64> certificateChain = Lists.newArrayList(Base64.encode(keystoreAccessor.getX509Certificate().getEncoded()));
            JWSHeader jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .x509CertChain(certificateChain)
                    .build();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .audience(properties.getOidc().getAudience())
                    .issuer(properties.getOidc().getClientId())
                    .claim("scope", StringUtils.replace(properties.getOidc().getScopes(), ",", " "))
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(Date.from(ZonedDateTime.now(ZoneOffset.UTC).toInstant()))
                    .expirationTime(Date.from(ZonedDateTime.now(ZoneOffset.UTC).toInstant().plusSeconds(EXPIRES_IN_SECONDS)))
                    .build();
            SignedJWT signedJWT = new SignedJWT(jwtHeader, claims);
            signedJWT.sign(jwsSigner);
            return signedJWT.serialize();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not get encoded certificate", e);
        } catch (JOSEException e) {
            throw new IllegalStateException("Error occurred during signing of JWT", e);
        }
    }

    private OidcTokenResponse fetchToken(String jwt) {
        LinkedMultiValueMap<String, String> requestParameters = new LinkedMultiValueMap<>();
        requestParameters.add("grant_type", JwtBearerGrantRequest.JWT_BEARER_GRANT_TYPE.getValue());
        requestParameters.add("assertion", jwt);
        return webClient.post()
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(requestParameters)
                .retrieve()
                .bodyToMono(OidcTokenResponse.class)
                .onErrorMap((Throwable error) -> {
                    OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                            "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: " + error.getMessage(), null);
                    throw new OAuth2AuthorizationException(oauth2Error);
                })
                .block(Duration.ofSeconds(BLOCK_DURATION_IN_SECONDS));
    }
}
