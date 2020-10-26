package no.digdir.efm.serviceregistry.controller;

import no.digdir.efm.serviceregistry.client.ServiceRegistryClient;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@RunWith(SpringRunner.class)
@WebMvcTest(ProxyController.class)
@AutoConfigureMockMvc
public class ProxyControllerTest {

    @MockBean
    private ServiceRegistryClient serviceRegistryClient;

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void lookupValidIdentifierTest() throws Exception {
        mockMvc.perform(get("/identifier/123")
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }
}
