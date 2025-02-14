package com.restaurant.api.authorizationserver.config;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@Validated
@Getter
@Setter
@ConfigurationProperties("authorization-server.auth")
public class AuthorizationServerSecurityProperties {

    @NotBlank
    private String providerUrl;

}
