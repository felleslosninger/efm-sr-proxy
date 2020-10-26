package no.digdir.efm.serviceregistry.keystore;

import no.difi.asic.SignatureHelper;
import no.digdir.efm.serviceregistry.config.KeyStoreProperties;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Class responsible for accessing the keystore.
 */
public class KeystoreAccessor {

    private final KeyStoreProperties properties;
    private final KeyStore keyStore;

    public KeystoreAccessor(KeyStoreProperties properties) {
        this.properties = Objects.requireNonNull(properties);
        this.keyStore = KeystoreProvider.loadKeyStore(properties);
        loadPrivateKey();
    }

    /**
     * Loads the private key from the keystore
     *
     * @return the private key
     */
    PrivateKey loadPrivateKey() {
        char[] password = properties.getPassword().toCharArray();
        try {
            return (PrivateKey) keyStore.getKey(properties.getAlias(), password);
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unexpected problem when operating KeyStore", e);
        } catch (UnrecoverableEntryException e) {
            throw new IllegalStateException(
                    String.format("No PrivateKey with alias \"%s\" found in the KeyStore or the provided Password is wrong", properties.getAlias()), e);
        }
    }

    public X509Certificate getX509Certificate() {
        try {
            if (!keyStore.containsAlias(properties.getAlias())) {
                throw new IllegalStateException(String.format("No Certificate with alias \"%s\" found in the KeyStore", properties.getAlias()));
            }
            return (X509Certificate) keyStore.getCertificate(properties.getAlias());
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Unexpected problem when operating KeyStore", e);
        }
    }

    public KeyPair getKeyPair() {
        PrivateKey privateKey = loadPrivateKey();
        X509Certificate certificate = getX509Certificate();
        return new KeyPair(certificate.getPublicKey(), privateKey);
    }

    public SignatureHelper getSignatureHelper() {
        return new MoveSignaturHelper(keyStore, properties.getAlias(), properties.getPassword());
    }


    public KeyStore getKeyStore() {
        return keyStore;
    }

    public class MoveSignaturHelper extends SignatureHelper {
        MoveSignaturHelper(KeyStore keyStore, String keyAlias, String keyPassword) {
            super(null);
            loadCertificate(keyStore, keyAlias, keyPassword);
        }
    }
}
