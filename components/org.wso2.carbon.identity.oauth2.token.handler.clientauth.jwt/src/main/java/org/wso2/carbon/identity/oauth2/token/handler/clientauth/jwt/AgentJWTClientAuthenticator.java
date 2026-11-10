/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.AbstractOAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.model.ClientAuthenticationMethodModel;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.AgentTokenValidator;

import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.AGENT_ENTITY_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.AGENT_JWT_ASSERTION_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.AGENT_JWT_CLIENT_AUTH_METHOD;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.AGENT_JWT_CLIENT_AUTH_METHOD_DISPLAY_NAME;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.AGENT_TOKEN;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.AUTHENTICATOR_TYPE_AGENT_JWT;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.AUTHENTICATOR_TYPE_PARAM;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.CIBA_ENDPOINT_PATH;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.CIBA_GRANT_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.CLIENT_ID_PARAM;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.GRANT_TYPE_PARAM;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.TOKEN_ENDPOINT_PATH;

/**
 * Client authentication handler that authenticates a CIBA back channel request as an autonomous agent, using the agent
 * access token this server issued to that agent as the client assertion.
 * <p>
 * The client being authenticated is taken from the {@code client_id} request parameter when present, and otherwise
 * from the token's {@code azp} claim. The token is deliberately <b>not</b> required to have been issued to that
 * client, so an agent may authenticate a client other than the one it obtained its token for.
 */
public class AgentJWTClientAuthenticator extends AbstractOAuthClientAuthenticator {

    private static final Log log = LogFactory.getLog(AgentJWTClientAuthenticator.class);

    /**
     * Returns whether the incoming request carries an agent JWT client assertion on an endpoint where it is accepted.
     *
     * @param httpServletRequest      Http servlet request.
     * @param bodyParameters          Map of request body params.
     * @param oAuthClientAuthnContext OAuthClientAuthnContext.
     * @return true if the incoming request can be handled.
     */
    @Override
    public boolean canAuthenticate(HttpServletRequest httpServletRequest, Map<String, List> bodyParameters,
                                   OAuthClientAuthnContext oAuthClientAuthnContext) {

        if (!isAgentJWTAssertionRequest(bodyParameters)) {
            return false;
        }
        if (!isAssertionAcceptedOnEndpoint(httpServletRequest, bodyParameters)) {
            log.warn("An agent JWT client assertion was presented to an endpoint where it is not accepted: "
                    + httpServletRequest.getRequestURI());
            return false;
        }
        return true;
    }

    /**
     * Validates the agent token and authenticates the request as the client the token was issued to.
     *
     * @param httpServletRequest      Http servlet request.
     * @param bodyParameters          Map of request body params.
     * @param oAuthClientAuthnContext OAuthClientAuthnContext.
     * @return true if the authentication is successful.
     * @throws OAuthClientAuthnException If the agent token is missing, malformed or not a valid agent token.
     */
    @Override
    public boolean authenticateClient(HttpServletRequest httpServletRequest, Map<String, List> bodyParameters,
                                      OAuthClientAuthnContext oAuthClientAuthnContext)
            throws OAuthClientAuthnException {

        oAuthClientAuthnContext.addParameter(AUTHENTICATOR_TYPE_PARAM, AUTHENTICATOR_TYPE_AGENT_JWT);

        SignedJWT agentToken = getAgentToken(bodyParameters, oAuthClientAuthnContext);
        String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
        AgentTokenValidator.validateAgentToken(agentToken, tenantDomain);

        /*
         * The agent the token was issued for is not logged here - validateAgentToken already logs it at debug level
         * for this same request, and reading it back would mean parsing the token's claims again.
         */
        if (log.isDebugEnabled()) {
            log.debug("Authenticated client: " + oAuthClientAuthnContext.getClientId() + " with an "
                    + AGENT_ENTITY_TYPE + " token.");
        }
        return true;
    }

    /**
     * Resolves the client id from the agent token's authorized party.
     *
     * @param httpServletRequest      Http servlet request.
     * @param bodyParameters          Map of request body params.
     * @param oAuthClientAuthnContext OAuthClientAuthnContext.
     * @return The client the agent token was issued to, or null if this is not an agent JWT request.
     * @throws OAuthClientAuthnException If the assertion cannot be parsed, carries no authorized party, or a
     *                                   {@code client_id} parameter naming a different client is sent with it.
     */
    @Override
    public String getClientId(HttpServletRequest httpServletRequest, Map<String, List> bodyParameters,
                              OAuthClientAuthnContext oAuthClientAuthnContext) throws OAuthClientAuthnException {

        if (!isAgentJWTAssertionRequest(bodyParameters)
                || !isAssertionAcceptedOnEndpoint(httpServletRequest, bodyParameters)) {
            // Not an agent JWT request. Let the remaining authenticators resolve the client id.
            return null;
        }

        SignedJWT agentToken = getAgentToken(bodyParameters, oAuthClientAuthnContext);
        JWTClaimsSet claimsSet;
        try {
            claimsSet = agentToken.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new OAuthClientAuthnException("Error while reading the claims of the agent token.",
                    OAuth2ErrorCodes.INVALID_CLIENT, e);
        }

        /*
         * The agent token is not required to have been issued to the client being authenticated, so an explicit
         * client_id parameter takes precedence and the token's authorized party is only a fallback for requests that
         * omit it.
         */
        String requestedClientId = getBodyParameters(bodyParameters).get(CLIENT_ID_PARAM);
        if (StringUtils.isNotBlank(requestedClientId)) {
            return requestedClientId;
        }
        String authorizedParty = AgentTokenValidator.resolveAuthorizedParty(claimsSet);
        if (StringUtils.isBlank(authorizedParty)) {
            throw new OAuthClientAuthnException("No client_id parameter was sent and the agent token does not carry "
                    + "an authorized party to fall back to.", OAuth2ErrorCodes.INVALID_CLIENT);
        }
        return authorizedParty;
    }

    /**
     * Retrieve the authentication methods supported by the authenticator.
     *
     * @return Authentication methods supported by the authenticator.
     */
    @Override
    public List<ClientAuthenticationMethodModel> getSupportedClientAuthenticationMethods() {

        return Collections.singletonList(new ClientAuthenticationMethodModel(AGENT_JWT_CLIENT_AUTH_METHOD,
                AGENT_JWT_CLIENT_AUTH_METHOD_DISPLAY_NAME));
    }

    private boolean isAgentJWTAssertionRequest(Map<String, List> bodyParameters) {

        Map<String, String> parameters = getBodyParameters(bodyParameters);
        return AGENT_JWT_ASSERTION_TYPE.equals(parameters.get(OAUTH_JWT_ASSERTION_TYPE))
                && StringUtils.isNotEmpty(parameters.get(OAUTH_JWT_ASSERTION));
    }

    /**
     * An agent token is a bearer credential, so it authenticates a client only on the endpoints of the agent
     * on-behalf-of flow: the CIBA backchannel authentication endpoint, and the token endpoint for the CIBA grant.
     */
    private boolean isAssertionAcceptedOnEndpoint(HttpServletRequest httpServletRequest,
                                                  Map<String, List> bodyParameters) {

        String requestPath = httpServletRequest.getRequestURI();
        if (StringUtils.isBlank(requestPath)) {
            return false;
        }
        if (StringUtils.endsWith(requestPath, CIBA_ENDPOINT_PATH)) {
            return true;
        }
        return StringUtils.endsWith(requestPath, TOKEN_ENDPOINT_PATH)
                && CIBA_GRANT_TYPE.equals(getBodyParameters(bodyParameters).get(GRANT_TYPE_PARAM));
    }

    private SignedJWT getAgentToken(Map<String, List> bodyParameters, OAuthClientAuthnContext oAuthClientAuthnContext)
            throws OAuthClientAuthnException {

        Object agentTokenFromContext = oAuthClientAuthnContext.getParameter(AGENT_TOKEN);
        if (agentTokenFromContext != null) {
            return (SignedJWT) agentTokenFromContext;
        }
        String assertion = getBodyParameters(bodyParameters).get(OAUTH_JWT_ASSERTION);
        if (isEmpty(assertion)) {
            throw new OAuthClientAuthnException("No agent token was found for " + AGENT_JWT_ASSERTION_TYPE,
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
        SignedJWT signedJWT;
        try {
            IdentityUtil.validateX5CLength(assertion);
            signedJWT = SignedJWT.parse(assertion);
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
            throw new OAuthClientAuthnException("Error while parsing the agent token.",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
        oAuthClientAuthnContext.addParameter(AGENT_TOKEN, signedJWT);
        return signedJWT;
    }
}
