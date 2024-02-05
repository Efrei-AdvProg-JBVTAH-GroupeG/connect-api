package fr.efrei.authenticator.configuration.properties;

import lombok.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "base.user")
public class BaseDataProperties {
    private String basePassword;
}
