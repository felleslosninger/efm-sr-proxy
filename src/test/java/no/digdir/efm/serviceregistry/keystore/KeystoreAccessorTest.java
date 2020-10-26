package no.digdir.efm.serviceregistry.keystore;

import com.google.common.io.ByteStreams;
import no.difi.asic.*;
import no.difi.commons.asic.jaxb.asic.Certificate;
import no.digdir.efm.serviceregistry.config.KeyStoreProperties;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * Created by Even
 */
public class KeystoreAccessorTest {

    private static final String FILE1_NAME = "file1.txt";

    private static final String ALIAS = "test";

    private static KeystoreAccessor keystoreAccessor;

    private static AsicWriterFactory asicWriterFactory = AsicWriterFactory.newFactory();

    private static AsicReaderFactory asicReaderFactory = AsicReaderFactory.newFactory();


    @BeforeClass
    public static void before() throws Exception {

        KeyStoreProperties properties = new KeyStoreProperties();
        properties.setAlias(ALIAS);
        properties.setPassword("changeit");
        properties.setPath(new ClassPathResource("/test.jks"));

        keystoreAccessor = new KeystoreAccessor(properties);
    }

    public static void performGetSignatureHelper(KeystoreAccessor keystoreAccessor, String alias) throws Exception {

        KeyStore keyStore = keystoreAccessor.getKeyStore();
        SignatureHelper signatureHelper = keystoreAccessor.getSignatureHelper();

        Assert.assertNotNull(signatureHelper);
        Assert.assertNotNull(keyStore);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            // Setup
            Assert.assertEquals("OutputStream is initially empty", 0, baos.size());

            AsicWriter asicWriter = asicWriterFactory.newContainer(baos);
            try (InputStream inputStream = KeystoreAccessorTest.class.getResourceAsStream("/" + FILE1_NAME)) {
                asicWriter.add(inputStream, FILE1_NAME, MimeType.forString("text/plain"));
            }
            asicWriter.sign(signatureHelper);

            Assert.assertNotEquals("OutputStream got content", 0, baos.size());
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        AsicReader asicReader = asicReaderFactory.open(bais);

        {
            // Check files was transferred correctly
            Assert.assertEquals("ASiC contains original file", FILE1_NAME, asicReader.getNextFile());
            asicReader.writeFile(ByteStreams.nullOutputStream()); // Consume file to advance to next entry and manifest

            Assert.assertNull("ASiC contains no further files", asicReader.getNextFile());

            Assert.assertEquals("ASiC contained a total of 1 file", 1, asicReader.getAsicManifest().getFile().size());

            // Check certificate used to sign the transferred file
            Assert.assertEquals("ASiC contained a total of 1 certificates", 1, asicReader.getAsicManifest().getCertificate().size());

            X509Certificate keyStoreCert = (X509Certificate) keyStore.getCertificate(alias);
            Certificate asicCert = asicReader.getAsicManifest().getCertificate().get(0);

            Assert.assertArrayEquals("ASiC file is signed by certificate from KeyStore",
                    keyStoreCert.getEncoded(),
                    asicCert.getCertificate());
        }
    }

    @Test
    public void testGetKeyPair() {

        KeyPair keyPair = keystoreAccessor.getKeyPair();

        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
    }

    @Test
    public void testGetSignatureHelper() throws Exception {
        performGetSignatureHelper(keystoreAccessor, ALIAS);
    }
}
