/*
 * Original:
 *   https://github.com/keycloak/keycloak/blob/18.0.2/services/src/main/java/org/keycloak/authentication/authenticators/browser/IdentityProviderAuthenticator.java
 */

package com.example.idpredirector;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.Authenticator;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.ClientSessionCode;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.Objects;
import java.util.Optional;

public class CustomIdpRedirector implements Authenticator {

    private static final Logger LOG = Logger.getLogger(CustomIdpRedirector.class);

    protected static final String ACCEPTS_PROMPT_NONE = "acceptsPromptNoneForwardFromClient";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (context.getUriInfo().getQueryParameters().containsKey(AdapterConstants.KC_IDP_HINT)) {
            String providerId = context.getUriInfo().getQueryParameters().getFirst(AdapterConstants.KC_IDP_HINT);
            if (providerId == null || providerId.equals("")) {
                LOG.tracef("Skipping: kc_idp_hint query parameter is empty");
                context.attempted();
            } else {
                LOG.tracef("Redirecting: %s set to %s", AdapterConstants.KC_IDP_HINT, providerId);
                redirect(context, providerId);
            }
        } else if (context.getAuthenticatorConfig() != null && context.getAuthenticatorConfig().getConfig().containsKey(CustomIdpRedirectorFactory.DEFAULT_PROVIDER)) {
            if (context.getForwardedErrorMessage() != null) {
                LOG.infof("Should redirect to remote IdP but forwardedError has value '%s', skipping this authenticator...", context.getForwardedErrorMessage());
                context.attempted();

                return;
            }

            String defaultProvider = context.getAuthenticatorConfig().getConfig().get(CustomIdpRedirectorFactory.DEFAULT_PROVIDER);
            LOG.tracef("Redirecting: default provider set to %s", defaultProvider);
            redirect(context, defaultProvider);
        } else {
            LOG.tracef("No default provider set or %s query parameter provided", AdapterConstants.KC_IDP_HINT);
            context.attempted();
        }
    }

    private void redirect(AuthenticationFlowContext context, String providerId) {
        Optional<IdentityProviderModel> idp = context.getRealm().getIdentityProvidersStream()
                .filter(IdentityProviderModel::isEnabled)
                .filter(identityProvider -> Objects.equals(providerId, identityProvider.getAlias()))
                .findFirst();
        if (idp.isPresent()) {
            String accessCode = new ClientSessionCode<>(context.getSession(), context.getRealm(), context.getAuthenticationSession()).getOrGenerateCode();
            String clientId = context.getAuthenticationSession().getClient().getClientId();
            String tabId = context.getAuthenticationSession().getTabId();
            URI location = Urls.identityProviderAuthnRequest(context.getUriInfo().getBaseUri(), providerId, context.getRealm().getName(), accessCode, clientId, tabId);
            if (context.getAuthenticationSession().getClientNote(OAuth2Constants.DISPLAY) != null) {
                location = UriBuilder.fromUri(location).queryParam(OAuth2Constants.DISPLAY, context.getAuthenticationSession().getClientNote(OAuth2Constants.DISPLAY)).build();
            }
            //// BEGIN
            MultivaluedMap<String, String> qparams = context.getUriInfo().getQueryParameters();
            qparams.forEach((k, mv) -> LOG.debugf("Got: %s, %s", k, mv));
            context.getAuthenticationSession().setAuthNote("my_client_id", qparams.getFirst("client_id"));
            context.getAuthenticationSession().setAuthNote("my_redirect_uri", qparams.getFirst("redirect_uri"));
            //location = UriBuilder.fromUri(location)
            //    .queryParam("hoge", "hoge-value")
            //    .queryParam("client_id", qparams.getFirst("client_id"))
            //    .queryParam("redirect_uri", qparams.getFirst("redirect_uri"))
            //    .build();
            //LOG.debugf("location is %s", location);
            //// END
            Response response = Response.seeOther(location)
                    .build();
            // will forward the request to the IDP with prompt=none if the IDP accepts forwards with prompt=none.
            if ("none".equals(context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.PROMPT_PARAM)) &&
                    Boolean.valueOf(idp.get().getConfig().get(ACCEPTS_PROMPT_NONE))) {
                context.getAuthenticationSession().setAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN, "true");
            }
            LOG.debugf("Redirecting to %s", providerId);
            context.forceChallenge(response);
            return;
        }

        LOG.warnf("Provider not found or not enabled for realm %s", providerId);
        context.attempted();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

}
