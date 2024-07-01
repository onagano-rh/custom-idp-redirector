/*
 * Original:
 *   https://github.com/keycloak/keycloak/blob/18.0.2/services/src/main/java/org/keycloak/broker/oidc/KeycloakOIDCIdentityProvider.java
 */

package com.example.oidcidp;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.headers.SecurityHeadersProvider;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.adapters.action.AdminAction;
import org.keycloak.representations.adapters.action.LogoutAction;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;

public class CustomOIDCIdentityProvider extends OIDCIdentityProvider {

    private static final Logger LOG = Logger.getLogger(CustomOIDCIdentityProvider.class);

    public static final String VALIDATED_ACCESS_TOKEN = "VALIDATED_ACCESS_TOKEN";

    public CustomOIDCIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new KeycloakEndpoint(callback, realm, event);
    }

    @Override
    protected void processAccessTokenResponse(BrokeredIdentityContext context, AccessTokenResponse response) {
        // Don't verify audience on accessToken as it may not be there. It was verified on IDToken already
        JsonWebToken access = validateToken(response.getToken(), true);
        context.getContextData().put(VALIDATED_ACCESS_TOKEN, access);
    }

    protected class KeycloakEndpoint extends OIDCEndpoint {
        public KeycloakEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            super(callback, realm, event);
        }

        @POST
        @Path(AdapterConstants.K_LOGOUT)
        public Response backchannelLogout(String input) {
            JWSInput token = null;
            try {
                token = new JWSInput(input);
            } catch (JWSInputException e) {
                logger.warn("Failed to verify logout request");
                return Response.status(400).build();
            }

            if (!verify(token)) {
                logger.warn("Failed to verify logout request");
                return Response.status(400).build();
            }

            LogoutAction action = null;
            try {
                action = JsonSerialization.readValue(token.getContent(), LogoutAction.class);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            if (!validateAction(action)) return Response.status(400).build();
            if (action.getKeycloakSessionIds() != null) {
                for (String sessionId : action.getKeycloakSessionIds()) {
                    String brokerSessionId = getConfig().getAlias() + "." + sessionId;
                    UserSessionModel userSession = session.sessions().getUserSessionByBrokerSessionId(realm, brokerSessionId);
                    if (userSession != null
                            && userSession.getState() != UserSessionModel.State.LOGGING_OUT
                            && userSession.getState() != UserSessionModel.State.LOGGED_OUT
                            ) {
                        AuthenticationManager.backchannelLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers, false);
                    }
                }

            }

            // TODO Empty content with ok makes no sense. Should it display a page? Or use noContent?
            session.getProvider(SecurityHeadersProvider.class).options().allowEmptyContentType();
            return Response.ok().build();
        }

        protected boolean validateAction(AdminAction action)  {
            if (!action.validate()) {
                logger.warn("admin request failed, not validated" + action.getAction());
                return false;
            }
            if (action.isExpired()) {
                logger.warn("admin request failed, expired token");
                return false;
            }
            if (!getConfig().getClientId().equals(action.getResource())) {
                logger.warn("Resource name does not match");
                return false;

            }
            return true;
        }

        @Override
        public SimpleHttp generateTokenRequest(String authorizationCode) {
            return super.generateTokenRequest(authorizationCode)
                    .param(AdapterConstants.CLIENT_SESSION_STATE, "n/a");  // hack to get backchannel logout to work

        }
    }

    @Override
    protected BrokeredIdentityContext exchangeExternalImpl(EventBuilder event, MultivaluedMap<String, String> params) {
        String subjectToken = params.getFirst(OAuth2Constants.SUBJECT_TOKEN);
        if (subjectToken == null) {
            event.detail(Details.REASON, OAuth2Constants.SUBJECT_TOKEN + " param unset");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "token not set", Response.Status.BAD_REQUEST);
        }
        String subjectTokenType = params.getFirst(OAuth2Constants.SUBJECT_TOKEN_TYPE);
        if (subjectTokenType == null) {
            subjectTokenType = OAuth2Constants.ACCESS_TOKEN_TYPE;
        }
        return validateJwt(event, subjectToken, subjectTokenType);
    }

    //// ADDED METHOD
    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        UriBuilder uriBuilder = super.createAuthorizationUrl(request);

        MultivaluedMap<String, String> qparams = request.getUriInfo().getQueryParameters();
        qparams.forEach((k, mv) -> LOG.debugf("Got: %s, %s", k, mv));
        String myClientId = request.getAuthenticationSession().getAuthNote("my_client_id");
        String myRedirectUri = request.getAuthenticationSession().getAuthNote("my_redirect_uri");
        LOG.debugf("got from auth session: %s, %s", myClientId, myRedirectUri);
        uriBuilder.queryParam("my_client_id", myClientId);
        uriBuilder.queryParam("my_redirect_uri", myRedirectUri);
        LOG.debugf("authorization url is %s", uriBuilder.build());

        return uriBuilder;
    }

}
