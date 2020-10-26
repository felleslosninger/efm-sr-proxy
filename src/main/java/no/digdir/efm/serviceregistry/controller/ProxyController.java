package no.digdir.efm.serviceregistry.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.digdir.efm.serviceregistry.client.ServiceRegistryClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

@Slf4j
@RestController
@RequiredArgsConstructor
public class ProxyController {

    private final ServiceRegistryClient serviceRegistryClient;

    @RequestMapping(value = "/identifier/{identifier}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> lookupEntityById(@PathVariable String identifier) {

        HttpStatus httpStatus = HttpStatus.OK;
        String result = "";
        try {
            result = serviceRegistryClient.lookupIdentifier(identifier);
        } catch (HttpClientErrorException e) {
            log.error("Client error exception occurred.", e);
            httpStatus = e.getStatusCode();
        }

        return new ResponseEntity<>(result, httpStatus);
    }

}
