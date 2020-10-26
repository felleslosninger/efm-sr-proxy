package no.digdir.efm.serviceregistry.oauth2;

import com.nimbusds.jose.JWSSigner;
import no.digdir.efm.serviceregistry.config.ClientConfigurationProperties;
import no.digdir.efm.serviceregistry.config.KeyStoreProperties;
import no.digdir.efm.serviceregistry.keystore.KeystoreAccessor;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.core.io.Resource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
public class JwtBearerAccessTokenResponseClientTests {

    @InjectMocks
    public JwtBearerAccessTokenResponseClient target;

    @Mock
    private ClientConfigurationProperties properties;
    @Mock
    private WebClient webClient;
    @Mock
    private KeystoreAccessor keystoreAccessor;
    @Mock
    private JWSSigner jwsSigner;
    @Mock
    private JwtBearerGrantRequest grantRequest;

    @Before
    public void setUp() throws Exception {
        ClientConfigurationProperties.Oidc oidc = mock(ClientConfigurationProperties.Oidc.class);
        when(oidc.getClientId()).thenReturn("ClientID");
        when(oidc.getAudience()).thenReturn("Audience");
        URL jwkUrl = new URL("http://jwk.url.here");
        when(oidc.getJwkUrl()).thenReturn(jwkUrl);
        KeyStoreProperties keyStoreProperties = mock(KeyStoreProperties.class);
        when(keyStoreProperties.getAlias()).thenReturn("alias");
        when(keyStoreProperties.getPassword()).thenReturn("password");
        Resource resource = mock(Resource.class);
        when(keyStoreProperties.getPath()).thenReturn(resource);
        when(keyStoreProperties.getType()).thenReturn("JKS");
        when(oidc.getKeystore()).thenReturn(keyStoreProperties);
        when(oidc.getRegistrationId()).thenReturn("RegistrationID");
        when(oidc.getScopes()).thenReturn("scope1,scope2");
        URL url = new URL("http://oidc.url.here");
        when(oidc.getUrl()).thenReturn(url);
        when(properties.getOidc()).thenReturn(oidc);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getTokenResponse_GrantRequestIsNull_ShouldThrowIllegalArgumentException() {
        target.getTokenResponse(null);
    }

    @Test(expected = IllegalStateException.class)
    public void getTokenResponse_CertificateEncodingFails_ShouldThrowIllegalArgumentException()
            throws CertificateEncodingException {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getEncoded()).thenThrow(new CertificateEncodingException("encoding failed"));
        when(keystoreAccessor.getX509Certificate()).thenReturn(certificate);
        target.getTokenResponse(grantRequest);
    }
}
