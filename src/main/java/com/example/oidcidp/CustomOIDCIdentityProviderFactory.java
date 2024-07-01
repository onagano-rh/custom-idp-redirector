/*
 * Original:
 *   https://github.com/keycloak/keycloak/blob/18.0.2/services/src/main/java/org/keycloak/broker/oidc/KeycloakOIDCIdentityProviderFactory.java
 */
package com.example.oidcidp;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
//import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

public class CustomOIDCIdentityProviderFactory extends AbstractIdentityProviderFactory<CustomOIDCIdentityProvider> {

    // Intentionally override the default ID to suppress 404 error of the following resource:
    //   /auth/resources/tbp2e/admin/rh-sso/partials/realm-identity-provider-custom-oidc.html
    //public static final String PROVIDER_ID = "custom-oidc";
    public static final String PROVIDER_ID = "oidc";

    @Override
    public String getName() {
        return "Custom OpenID Connect";
    }

    @Override
    public CustomOIDCIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new CustomOIDCIdentityProvider(session, new OIDCIdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, InputStream inputStream) {
        // Copy & paset because of the protected visibility
        //return OIDCIdentityProviderFactory.parseOIDCConfig(session, inputStream);
        OIDCConfigurationRepresentation rep;
        try {
            rep = JsonSerialization.readValue(inputStream, OIDCConfigurationRepresentation.class);
        } catch (IOException e) {
            throw new RuntimeException("failed to load openid connect metadata", e);
        }
        OIDCIdentityProviderConfig config = new OIDCIdentityProviderConfig();
        config.setIssuer(rep.getIssuer());
        config.setLogoutUrl(rep.getLogoutEndpoint());
        config.setAuthorizationUrl(rep.getAuthorizationEndpoint());
        config.setTokenUrl(rep.getTokenEndpoint());
        config.setUserInfoUrl(rep.getUserinfoEndpoint());
        if (rep.getJwksUri() != null) {
            config.setValidateSignature(true);
            config.setUseJwksUrl(true);
            config.setJwksUrl(rep.getJwksUri());
        }
        return config.getConfig();
    }

    @Override
    public OIDCIdentityProviderConfig createConfig() {
        return new OIDCIdentityProviderConfig();
    }
}
