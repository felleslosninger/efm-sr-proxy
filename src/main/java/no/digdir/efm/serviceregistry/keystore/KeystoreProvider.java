package no.digdir.efm.serviceregistry.keystore;

import lombok.RequiredArgsConstructor;
import no.digdir.efm.serviceregistry.config.KeyStoreProperties;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@RequiredArgsConstructor
public class KeystoreProvider {

    private final KeyStore keystore;

    static KeyStore loadKeyStore(KeyStoreProperties properties) {
        String type = properties.getType();
        String password = properties.getPassword();
        Resource path = properties.getPath();
        try {
            KeyStore keyStore = KeyStore.getInstance(type);
            if (path == null || "none".equalsIgnoreCase(path.getFilename())) {
                keyStore.load(null, password.toCharArray());
            } else {
                keyStore.load(path.getInputStream(), password.toCharArray());
            }
            return keyStore;

        } catch (KeyStoreException e) {
            throw new IllegalStateException("Unable to load KeyStore", e);

        } catch (IOException e) {
            throw new IllegalStateException("Could not open keystore file", e);

        } catch (CertificateException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to load keystore file", e);
        }
    }

}
