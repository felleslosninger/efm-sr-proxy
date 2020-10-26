package no.digdir.efm.serviceregistry.oauth2;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

@Data
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class OidcTokenResponse {

    private String accessToken;
    private Integer expiresIn;
    private String scope;
    private String tokenType;
}
