package no.digdir.efm.serviceregistry;

import no.digdir.efm.serviceregistry.config.ProxyConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

@SpringBootTest
@ContextConfiguration(classes = {SrProxyApplication.class, ProxyConfiguration.class})
class SrProxyApplicationTests {

    @Test
    void contextLoads() {
    }

}
