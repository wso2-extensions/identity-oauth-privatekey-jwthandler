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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceComponent;
import org.wso2.carbon.identity.oauth2.util.JWTSignatureValidationUtils;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.text.ParseException;
import java.util.Map;

import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.ACCOUNT_DISABLED_CLAIM;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.ACCOUNT_LOCKED_CLAIM;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.AGENT_ENTITY_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.AUTHENTICATED_ENTITY_CLAIM;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.AUTHORIZED_PARTY_CLAIM;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.CLIENT_ID_CLAIM;

/**
 * Validates an agent access token presented as a client assertion.
 */
public class AgentTokenValidator {

    private static final Log log = LogFactory.getLog(AgentTokenValidator.class);

    private AgentTokenValidator() {

    }

    /**
     * Validates the given agent token, throwing if it is not one this server issued for an agent that can still act.
     *
     * @param signedJWT    Parsed agent token.
     * @param tenantDomain Tenant domain the request is served in.
     * @throws OAuthClientAuthnException If the token is not a valid, unexpired agent token issued by this server.
     */
    public static void validateAgentToken(SignedJWT signedJWT, String tenantDomain)
            throws OAuthClientAuthnException {

        try {
            JWTClaimsSet claimsSet = JWTUtils.getJWTClaimSet(signedJWT).orElseThrow(
                    () -> new OAuthClientAuthnException("Claim values are empty in the given agent token.",
                            OAuth2ErrorCodes.INVALID_CLIENT));
            JWTUtils.validateMandatoryClaims(claimsSet);

            /*
             * The agent token is minted by this server, so its issuer must be this server's token issuer. Checking
             * this before resolving the identity provider keeps a foreign JWT from reaching the IDP lookup at all.
             */
            String jwtIssuer = claimsSet.getIssuer();
            String expectedIssuer = OAuth2Util.getIdTokenIssuer(tenantDomain);
            if (!StringUtils.equals(expectedIssuer, jwtIssuer)) {
                throw new OAuthClientAuthnException("Invalid issuer in the agent token. Expected: " + expectedIssuer
                        + ", Received: " + jwtIssuer, OAuth2ErrorCodes.INVALID_CLIENT);
            }

            IdentityProvider identityProvider = OAuth2Util.getIdentityProviderWithJWTIssuer(jwtIssuer, tenantDomain);
            if (!JWTSignatureValidationUtils.validateSignature(signedJWT, identityProvider, tenantDomain)) {
                throw new OAuthClientAuthnException("Signature validation failed for the agent token.",
                        OAuth2ErrorCodes.INVALID_CLIENT);
            }

            if (!JWTUtils.checkExpirationTime(claimsSet.getExpirationTime())) {
                throw new OAuthClientAuthnException("Agent token has expired.", OAuth2ErrorCodes.INVALID_CLIENT);
            }
            JWTUtils.checkNotBeforeTime(claimsSet.getNotBeforeTime());

            /*
             * Only a token issued for an agent may authenticate a client this way. Without this check any access
             * token issued by this server - including a user's - would be accepted as a client credential.
             */
            String authenticatedEntity = claimsSet.getStringClaim(AUTHENTICATED_ENTITY_CLAIM);
            if (!AGENT_ENTITY_TYPE.equals(authenticatedEntity)) {
                throw new OAuthClientAuthnException("The client assertion is not an agent token. Expected '"
                        + AUTHENTICATED_ENTITY_CLAIM + "' claim: " + AGENT_ENTITY_TYPE + ", Received: "
                        + authenticatedEntity, OAuth2ErrorCodes.INVALID_CLIENT);
            }

            String agentId = claimsSet.getSubject();
            if (StringUtils.isBlank(agentId)) {
                throw new OAuthClientAuthnException("The agent token does not carry the agent id in the 'sub' claim.",
                        OAuth2ErrorCodes.INVALID_CLIENT);
            }
            validateAgentAccountState(agentId, tenantDomain);

            if (log.isDebugEnabled()) {
                log.debug("Agent token validated for agent: " + agentId);
            }
        } catch (OAuthClientAuthnException e) {
            /*
             * OAuthClientAuthnException is an IdentityOAuth2Exception, so the specific failures raised above have to
             * be rethrown before the catch below turns them into a generic message.
             */
            throw e;
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthClientAuthnException("Error while validating the agent token.",
                    OAuth2ErrorCodes.INVALID_CLIENT, e);
        } catch (ParseException e) {
            throw new OAuthClientAuthnException("Error while reading the claims of the agent token.",
                    OAuth2ErrorCodes.INVALID_CLIENT, e);
        }
    }

    /**
     * Rejects the assertion if the agent it was issued for can no longer act.
     *
     * @param agentId      Agent id carried in the {@code sub} claim of the token.
     * @param tenantDomain Tenant domain the request is served in.
     * @throws OAuthClientAuthnException If the agent does not exist, is locked, is disabled, or its state cannot be
     *                                   resolved.
     */
    private static void validateAgentAccountState(String agentId, String tenantDomain)
            throws OAuthClientAuthnException {

        AbstractUserStoreManager userStoreManager = getUserStoreManager(tenantDomain);
        Map<String, String> accountState;
        try {
            /*
             * The agent lives in the AGENT user store domain, but the id is resolved against every domain of the
             * tenant realm, so no domain is assumed here.
             */
            if (!userStoreManager.isExistingUserWithID(agentId)) {
                throw new OAuthClientAuthnException("The agent of the given agent token does not exist: " + agentId,
                        OAuth2ErrorCodes.INVALID_CLIENT);
            }
            accountState = userStoreManager.getUserClaimValuesWithID(agentId,
                    new String[]{ACCOUNT_LOCKED_CLAIM, ACCOUNT_DISABLED_CLAIM}, null);
        } catch (UserStoreException e) {
            throw new OAuthClientAuthnException("Error while resolving the account state of the agent: " + agentId,
                    OAuth2ErrorCodes.INVALID_CLIENT, e);
        }

        if (Boolean.parseBoolean(accountState.get(ACCOUNT_DISABLED_CLAIM))) {
            throw new OAuthClientAuthnException("The agent of the given agent token is disabled: " + agentId,
                    OAuth2ErrorCodes.INVALID_CLIENT);
        }
        if (Boolean.parseBoolean(accountState.get(ACCOUNT_LOCKED_CLAIM))) {
            throw new OAuthClientAuthnException("The agent of the given agent token is locked: " + agentId,
                    OAuth2ErrorCodes.INVALID_CLIENT);
        }
    }

    private static AbstractUserStoreManager getUserStoreManager(String tenantDomain)
            throws OAuthClientAuthnException {

        RealmService realmService = JWTServiceComponent.getRealmService();
        if (realmService == null) {
            throw new OAuthClientAuthnException("RealmService is not available to resolve the account state of the "
                    + "agent.", OAuth2ErrorCodes.SERVER_ERROR);
        }
        try {
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            if (!(userStoreManager instanceof AbstractUserStoreManager)) {
                throw new OAuthClientAuthnException("The user store manager of tenant: " + tenantDomain + " does not "
                        + "support resolving a user by id.", OAuth2ErrorCodes.SERVER_ERROR);
            }
            return (AbstractUserStoreManager) userStoreManager;
        } catch (UserStoreException e) {
            throw new OAuthClientAuthnException("Error while retrieving the user store manager of tenant: "
                    + tenantDomain, OAuth2ErrorCodes.SERVER_ERROR, e);
        }
    }

    /**
     * Resolves the client the agent token was issued to. RFC 7521 section 4.2 identifies the client by the assertion
     * itself; for an agent token that is the authorized party rather than the subject, since the subject is the agent.
     *
     * @param claimsSet Claim set of the agent token.
     * @return The client id the agent token was issued to, or {@code null} if it cannot be resolved.
     */
    public static String resolveAuthorizedParty(JWTClaimsSet claimsSet) {

        try {
            String authorizedParty = claimsSet.getStringClaim(AUTHORIZED_PARTY_CLAIM);
            if (StringUtils.isNotBlank(authorizedParty)) {
                return authorizedParty;
            }
            return claimsSet.getStringClaim(CLIENT_ID_CLAIM);
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while reading the authorized party of the agent token.", e);
            }
            return null;
        }
    }
}
