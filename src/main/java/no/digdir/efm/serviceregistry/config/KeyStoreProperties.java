package no.digdir.efm.serviceregistry.config;

import lombok.Data;
import lombok.ToString;
import org.springframework.core.io.Resource;

import javax.validation.constraints.NotNull;
import java.security.KeyStore;

@Data
@ToString(exclude = "password")
public class KeyStoreProperties {

    /**
     * Type of KeyStore
     *
     * Examples: JKS, Windows-MY
     */
    private String type = KeyStore.getDefaultType();

    /**
     * Keystore alias for key.
     */
    @NotNull
    private String alias;

    /**
     * Path of jks file.
     *
     * May be empty if type = Windows-MY
     */
    private Resource path;

    /**
     * Password of keystore and entry.
     */
    @NotNull
    private String password = "";

}

