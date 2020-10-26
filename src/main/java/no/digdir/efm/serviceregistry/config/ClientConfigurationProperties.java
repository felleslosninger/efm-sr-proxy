package no.digdir.efm.serviceregistry.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.net.URL;

@Data
@Validated
@ConfigurationProperties("client")
public class ClientConfigurationProperties {

    /**
     * Service registry endpoint.
     */
    @NotNull(message = "Service registry endpoint must be configured")
    private URL endpointURL;

    @Valid
    private Oidc oidc;

    @Data
    public static class Oidc {
        @NotNull
        private String registrationId;
        @NotNull
        private String clientId;
        private URL url;
        @NestedConfigurationProperty
        private KeyStoreProperties keystore;
        @NotNull
        private String audience;
        @NotNull
        private String scopes;
        @NotNull
        private URL jwkUrl;
    }

}
