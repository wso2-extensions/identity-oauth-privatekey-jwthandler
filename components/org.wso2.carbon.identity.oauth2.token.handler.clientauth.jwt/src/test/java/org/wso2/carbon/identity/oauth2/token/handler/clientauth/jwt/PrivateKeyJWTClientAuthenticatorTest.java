/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.ClientAuthenticationMethodModel;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.JWTAuthenticationConfigurationDAO;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceComponent;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.internal.IdpMgtServiceComponentHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.security.Key;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_BEARER_GRANT_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.buildJWT;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.getKeyStoreFromFile;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.JWTValidatorTest.TEST_CLIENT_ID_1;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2CarbonDB", files = {"dbscripts/identity.sql"})
@WithRealmService(tenantId = SUPER_TENANT_ID, tenantDomain = SUPER_TENANT_DOMAIN_NAME,
        injectToSingletons = {JWTServiceComponent.class})
@WithKeyStore
public class PrivateKeyJWTClientAuthenticatorTest {

    private static final String INVALID_SIGNATURE_ALGORITHM_ERROR =
            "Signature algorithm used in the request is invalid.";
    private static final String PROP_TOKEN_EP = "OAuth2TokenEPUrl";

    PrivateKeyJWTClientAuthenticator privateKeyJWTClientAuthenticator;
    HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);

    OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();

    KeyStore clientKeyStore;
    Key key1;
    String audience;

    @BeforeClass
    public void setUp() throws Exception {

        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        key1 = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        audience = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);
        privateKeyJWTClientAuthenticator = new PrivateKeyJWTClientAuthenticator();
    }

    @Test
    public void testGetClientId() throws Exception {

        Map<String, List> bodyContent = new HashMap<>();
        List<String> assertion = new ArrayList<>();
        assertion.add(buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", audience, "RSA265", key1,
                0));
        bodyContent.put(OAUTH_JWT_ASSERTION, assertion);
        String clientId = privateKeyJWTClientAuthenticator.getClientId(httpServletRequest, bodyContent,
                oAuthClientAuthnContext);
        assertEquals(clientId, "KrVLov4Bl3natUksF2HmWsdw684a", "The expected client id is the jwt " +
                "subject.");

    }

    @Test
    public void testcanAuthenticate() throws IdentityOAuth2Exception {

        Map<String, List> bodyContent = new HashMap<>();
        List<String> assertion = new ArrayList<>();
        List<String> assertionType = new ArrayList<>();
        assertion.add(buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", audience, "RSA265", key1,
                0));
        assertionType.add(OAUTH_JWT_BEARER_GRANT_TYPE);
        bodyContent.put(OAUTH_JWT_ASSERTION, assertion);

        bodyContent.put(OAUTH_JWT_ASSERTION_TYPE, assertionType);
        boolean received = privateKeyJWTClientAuthenticator.canAuthenticate(httpServletRequest, bodyContent,
                oAuthClientAuthnContext);
        assertEquals(received, true, "A valid request refused to authenticate.");
    }

    @Test
    public void testPrivateKeyJWTFlagAdded() throws Exception {

        Map<String, List> bodyContent = new HashMap<>();
        List<String> assertionType = new ArrayList<>();
        assertionType.add(OAUTH_JWT_BEARER_GRANT_TYPE);
        List<String> assertion = new ArrayList<>();
        assertion.add(buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", audience, "RSA265", key1,
                0));
        bodyContent.put(OAUTH_JWT_ASSERTION, assertion);
        bodyContent.put(OAUTH_JWT_ASSERTION_TYPE, assertionType);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm = realmService.getTenantUserRealm(SUPER_TENANT_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(userRealm);
        JWTServiceDataHolder.getInstance().setRealmService(realmService);
        IdpMgtServiceComponentHolder.getInstance().setRealmService(realmService);
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("OAuth.OpenIDConnect.IDTokenIssuerID", "http://localhost:9443/oauth2/token");
        JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig = new JWTClientAuthenticatorConfig();
        jwtClientAuthenticatorConfig.setEnableTokenReuse(true);
        JWTAuthenticationConfigurationDAO mockDAO = Mockito.mock(JWTAuthenticationConfigurationDAO
                .class);
        Mockito.when(mockDAO.getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(Mockito.anyString()))
                .thenReturn(jwtClientAuthenticatorConfig);
        JWTServiceDataHolder.getInstance()
                .setJwtAuthenticationConfigurationDAO(mockDAO);
        Mockito.when(httpServletRequest.getRequestURL())
                .thenReturn(new StringBuffer("http://localhost:9443/oauth2/token"));

        OAuthAppDO mockAppDO = new OAuthAppDO();
        mockAppDO.setOauthConsumerKey(TEST_CLIENT_ID_1);
        AuthenticatedUser appOwner = new AuthenticatedUser();
        appOwner.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        mockAppDO.setAppOwner(appOwner);

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class,
                Mockito.CALLS_REAL_METHODS)) {
            mockedOAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(Mockito.anyString()))
                    .thenReturn(mockAppDO);
            try {
                privateKeyJWTClientAuthenticator.authenticateClient(httpServletRequest, bodyContent,
                        oAuthClientAuthnContext);
                assertEquals(Constants.AUTHENTICATOR_TYPE_PK_JWT, oAuthClientAuthnContext.getParameter(
                        Constants.AUTHENTICATOR_TYPE_PARAM));
            } catch (OAuthClientAuthnException e) {
                assertEquals(Constants.AUTHENTICATOR_TYPE_PK_JWT, oAuthClientAuthnContext.getParameter(
                        Constants.AUTHENTICATOR_TYPE_PARAM));
            }
        }
    }

    @DataProvider(name = "provideConfiguredSignatureAlgorithm")
    public Object[][] provideConfiguredSignatureAlgorithm() {

        return new Object[][]{
                //   The Java signature algorithm name of RS256, as offered by the Console.
                {"SHA256withRSA", "3040"},
                //   The JWS algorithm name of the same algorithm.
                {"RS256", "3041"},
        };
    }

    /**
     * A client assertion signed with RS256 must not be rejected for an invalid signature algorithm when the
     * application is configured with an algorithm that is equivalent to RS256, regardless of whether it is stored
     * using the Java signature algorithm name or the JWS algorithm name.
     */
    @Test(dataProvider = "provideConfiguredSignatureAlgorithm")
    public void testAssertionIsNotRejectedForEquivalentSignatureAlgorithm(String configuredSignatureAlgorithm,
                                                                          String jti) throws Exception {

        Map<String, List> bodyContent = new HashMap<>();
        List<String> assertionType = new ArrayList<>();
        assertionType.add(OAUTH_JWT_BEARER_GRANT_TYPE);
        List<String> assertion = new ArrayList<>();
        //   buildJWT signs with RS256 unless RS512 or none is requested.
        assertion.add(buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, jti, audience, "RS256", key1, 0));
        bodyContent.put(OAUTH_JWT_ASSERTION, assertion);
        bodyContent.put(OAUTH_JWT_ASSERTION_TYPE, assertionType);

        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm = realmService.getTenantUserRealm(SUPER_TENANT_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(userRealm);
        JWTServiceDataHolder.getInstance().setRealmService(realmService);
        IdpMgtServiceComponentHolder.getInstance().setRealmService(realmService);

        JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig = new JWTClientAuthenticatorConfig();
        jwtClientAuthenticatorConfig.setEnableTokenReuse(true);
        JWTAuthenticationConfigurationDAO mockDAO = Mockito.mock(JWTAuthenticationConfigurationDAO.class);
        Mockito.when(mockDAO.getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(Mockito.anyString()))
                .thenReturn(jwtClientAuthenticatorConfig);
        JWTServiceDataHolder.getInstance().setJwtAuthenticationConfigurationDAO(mockDAO);
        Mockito.when(httpServletRequest.getRequestURL())
                .thenReturn(new StringBuffer("http://localhost:9443/oauth2/token"));

        OAuthAppDO mockAppDO = new OAuthAppDO();
        mockAppDO.setOauthConsumerKey(TEST_CLIENT_ID_1);
        mockAppDO.setTokenEndpointAuthSignatureAlgorithm(configuredSignatureAlgorithm);
        AuthenticatedUser appOwner = new AuthenticatedUser();
        appOwner.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        mockAppDO.setAppOwner(appOwner);

        /* The audience of the assertion is validated against the token endpoint of the resident IdP before the
           signature algorithm is validated, so the resident IdP has to resolve for the check to be reached. */
        Property tokenEndpoint = new Property();
        tokenEndpoint.setName(PROP_TOKEN_EP);
        tokenEndpoint.setValue(audience);
        FederatedAuthenticatorConfig oidcConfig = new FederatedAuthenticatorConfig();
        oidcConfig.setName(IdentityApplicationConstants.Authenticator.OIDC.NAME);
        oidcConfig.setProperties(new Property[]{tokenEndpoint});
        IdentityProvider residentIdp = new IdentityProvider();
        residentIdp.setFederatedAuthenticatorConfigs(new FederatedAuthenticatorConfig[]{oidcConfig});
        IdentityProviderManager mockIdpManager = Mockito.mock(IdentityProviderManager.class);
        Mockito.when(mockIdpManager.getResidentIdP(Mockito.anyString())).thenReturn(residentIdp);

        /* The signature is verified after the algorithm check. No certificate is configured on the service provider
           here, so verification falls back to the tenant keystore. */
        ServiceProvider serviceProvider = Mockito.mock(ServiceProvider.class);
        Mockito.when(serviceProvider.getCertificateContent()).thenReturn(null);
        Mockito.when(serviceProvider.getSpProperties()).thenReturn(new ServiceProviderProperty[0]);
        ApplicationManagementService applicationMgtService = Mockito.mock(ApplicationManagementService.class);
        Mockito.when(applicationMgtService.getServiceProviderByClientId(Mockito.anyString(), Mockito.anyString(),
                Mockito.anyString())).thenReturn(serviceProvider);
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationMgtService);

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class,
                     Mockito.CALLS_REAL_METHODS);
             MockedStatic<IdentityProviderManager> mockedIdpManagerStatic =
                     Mockito.mockStatic(IdentityProviderManager.class)) {
            mockedOAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(Mockito.anyString()))
                    .thenReturn(mockAppDO);
            mockedOAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(Mockito.anyString(),
                    Mockito.anyString())).thenReturn(mockAppDO);
            mockedIdpManagerStatic.when(IdentityProviderManager::getInstance).thenReturn(mockIdpManager);
            try {
                //   A dedicated context per invocation, since authenticateClient cannot overwrite an existing key.
                privateKeyJWTClientAuthenticator.authenticateClient(httpServletRequest, bodyContent,
                        new OAuthClientAuthnContext());
            } catch (OAuthClientAuthnException e) {
                /* Validation can still fail for later reasons in this test setup, such as the signature itself not
                   being verifiable, but it must never fail because the signature algorithm was considered invalid. */
                Assert.assertNotEquals(e.getMessage(), INVALID_SIGNATURE_ALGORITHM_ERROR,
                        "A client assertion signed with RS256 was rejected while the application was configured "
                                + "with the equivalent algorithm: " + configuredSignatureAlgorithm);
            }
        }
    }

    @Test
    public void testGetSupportedClientAuthenticationMethods() {

        List<String> supportedAuthMethods = new ArrayList<>();
        for (ClientAuthenticationMethodModel clientAuthenticationMethodModel : privateKeyJWTClientAuthenticator
                .getSupportedClientAuthenticationMethods()) {
            supportedAuthMethods.add(clientAuthenticationMethodModel.getName());
        }
        Assert.assertTrue(supportedAuthMethods.contains("private_key_jwt"));
        assertEquals(supportedAuthMethods.size(), 1);
    }
}
