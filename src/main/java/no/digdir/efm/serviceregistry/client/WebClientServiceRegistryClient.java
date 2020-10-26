package no.digdir.efm.serviceregistry.client;

import com.nimbusds.jose.proc.BadJWSException;
import lombok.RequiredArgsConstructor;
import no.difi.move.common.oauth.JWTDecoder;
import no.digdir.efm.serviceregistry.config.ClientConfigurationProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.cert.CertificateException;
import java.time.Duration;

@Service
@RequiredArgsConstructor
public class WebClientServiceRegistryClient implements ServiceRegistryClient {

    private static final long BLOCK_DURATION_IN_SECONDS = 30;

    @Qualifier("ServiceRegistryWebClient")
    private final WebClient webClient;
    private final ClientConfigurationProperties properties;

    @Override
    public String lookupIdentifier(String identifier) {
        try {
            String response = webClient.get()
                    .uri("/{id}", identifier)
                    .header("Accept", "application/jose", "application/json")
                    .retrieve()
                    .bodyToMono(String.class)
                    .block(Duration.ofSeconds(BLOCK_DURATION_IN_SECONDS));
            JWTDecoder jwtDecoder = new JWTDecoder();
            return jwtDecoder.getPayload(response, properties.getOidc().getJwkUrl());
        } catch (BadJWSException | CertificateException e) {
            throw new IllegalStateException("JWT decoding failed", e);
        }
    }
}
