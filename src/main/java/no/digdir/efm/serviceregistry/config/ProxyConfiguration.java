package no.digdir.efm.serviceregistry.config;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import no.digdir.efm.serviceregistry.keystore.KeystoreAccessor;
import no.digdir.efm.serviceregistry.oauth2.JwtBearerGrantRequest;
import no.digdir.efm.serviceregistry.oauth2.JwtBearerOAuth2AuthorizedClientProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
@EnableRetry
@EnableConfigurationProperties(ClientConfigurationProperties.class)
public class ProxyConfiguration {

    @Bean
    ClientRegistration clientRegistration(ClientConfigurationProperties properties) {
        return ClientRegistration.withRegistrationId(properties.getOidc().getRegistrationId())
                .authorizationGrantType(JwtBearerGrantRequest.JWT_BEARER_GRANT_TYPE)
                .build();
    }

    @Bean(name = "ServiceRegistryWebClient")
    WebClient serviceRegistryWebClient(ClientConfigurationProperties properties,
                                       ClientRegistration clientRegistration,
                                       JwtBearerOAuth2AuthorizedClientProvider clientProvider) {
        ClientRegistrationRepository registrationRepository = new InMemoryClientRegistrationRepository(clientRegistration);
        OAuth2AuthorizedClientService authorizedClientService = new InMemoryOAuth2AuthorizedClientService(registrationRepository);
        AuthorizedClientServiceOAuth2AuthorizedClientManager clientManager
                = new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrationRepository, authorizedClientService);
        OAuth2AuthorizedClientProvider authorizedClientProvider
                = OAuth2AuthorizedClientProviderBuilder.builder()
                .provider(clientProvider)
                .build();
        clientManager.setAuthorizedClientProvider(authorizedClientProvider);
        ServletOAuth2AuthorizedClientExchangeFilterFunction filter
                = new ServletOAuth2AuthorizedClientExchangeFilterFunction(clientManager);
        filter.setDefaultClientRegistrationId(properties.getOidc().getRegistrationId());
        filter.setDefaultOAuth2AuthorizedClient(true);

        return WebClient.builder()
                .apply(filter.oauth2Configuration())
                .baseUrl(properties.getEndpointURL().toString())
                .build();
    }

    @Bean(name = "OidcProviderWebClient")
    WebClient maskinportenWebClient(ClientConfigurationProperties properties) {
        return WebClient.builder()
                .baseUrl(properties.getOidc().getUrl().toString())
                .build();
    }

    @Bean
    KeystoreAccessor keystoreAccessor(ClientConfigurationProperties properties) {
        return new KeystoreAccessor(properties.getOidc().getKeystore());
    }

    @Bean
    JWSSigner jwsSigner(KeystoreAccessor accessor) {
        return new RSASSASigner(accessor.getKeyPair().getPrivate());
    }
}
