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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.storage;

import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.JdbcUtils;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao.JWTEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao.JWTStorageManager;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil;

import java.sql.Connection;
import java.util.List;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.closeH2Base;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.initiateH2Base;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.spyConnection;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.Util.checkIfTenantIdColumnIsAvailableInIdnOidcAuthTable;

public class JWTStorageManagerTest {

    private JWTStorageManager jwtStorageManager;
    private Connection spyConnection;

    private MockedStatic<IdentityDatabaseUtil> mockedIdentityDatabaseUtil;
    private MockedStatic<JdbcUtils> mockedJdbcUtils;
    private MockedStatic<FrameworkUtils> mockedFrameworkUtils;


    @BeforeClass
    public void setUp() throws Exception {

        initiateH2Base();
        jwtStorageManager = new JWTStorageManager();
    }

    @BeforeMethod
    public void init() throws Exception {

        mockedIdentityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        spyConnection = spyConnection(JWTTestUtil.getConnection());
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(spyConnection);
        mockedJdbcUtils = mockStatic(JdbcUtils.class);
        mockedFrameworkUtils = mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.isTableColumnExists(Constants.SQLQueries.IDN_OIDC_JTI,
                Constants.SQLQueries.TENANT_ID)).thenReturn(true);
        checkIfTenantIdColumnIsAvailableInIdnOidcAuthTable();

    }

    @AfterMethod
    public void tearDownMethod() {

        try {
            if (spyConnection != null && !spyConnection.isClosed()) {
                spyConnection.close();
            }
        } catch (Exception e) {
            // Ignore
        }
        if (mockedIdentityDatabaseUtil != null) {
            mockedIdentityDatabaseUtil.close();
        }
        if (mockedJdbcUtils != null) {
            mockedJdbcUtils.close();
        }
        if (mockedFrameworkUtils != null) {
            mockedFrameworkUtils.close();
        }
    }

    @AfterClass
    public void tearDown() throws Exception {

        closeH2Base();
    }

    @Test()
    public void testIsJTIExistsInDB() throws Exception {

        assertFalse(jwtStorageManager.isJTIExistsInDB("2000"));
    }

    @Test()
    public void testPersistJWTIdInDB() throws Exception {

        JWTServiceDataHolder.getInstance().setPreventTokenReuse(true);
        jwtStorageManager.persistJWTIdInDB("2023", -1234, 10000000, 10000000,
                true);
    }

    @Test(expectedExceptions = OAuthClientAuthnException.class)
    public void testPersistJWTIdInDBExceptionCase() throws Exception {

        jwtStorageManager.persistJWTIdInDB("2000", -1234, 10000000, 10000000, true);
    }

    @Test
    public void testDefaultPersistJWTIdInDB() throws Exception {

        jwtStorageManager.persistJWTIdInDB("2026", -1234, 10000000, 10000000);
    }

    @Test()
    public void testGetJwtsFromDB() throws Exception {

        List<JWTEntry> jwtEntryList = jwtStorageManager.getJwtsFromDB("10010010", 1);
        assertNotNull(jwtEntryList);
        JWTEntry jwtEntry = jwtEntryList.get(0);
        assertEquals(1, jwtEntry.getTenantId());
    }

    @Test()
    public void testPersistJWTIdInDBWithoutTokenReuse() throws Exception {

        JWTServiceDataHolder.getInstance().setPreventTokenReuse(false);
        when(JdbcUtils.isH2DB()).thenReturn(true);
        when(JdbcUtils.isOracleDB()).thenReturn(false);
        // Insert a JTI entry with Expired Date.
        jwtStorageManager.persistJWTIdInDB("2023", 12, 10000000, 10000000,
                false);
        when(JdbcUtils.isH2DB()).thenReturn(true);
        when(JdbcUtils.isOracleDB()).thenReturn(false);
        // Update a JTI entry again.
        jwtStorageManager.persistJWTIdInDB("2023", 12, 10001000, 10000100,
                false);
    }

    @Test(dependsOnMethods = {"testPersistJWTIdInDBWithoutTokenReuse"})
    public void testUpdatedJTIEntry() throws Exception {

        JWTServiceDataHolder.getInstance().setPreventTokenReuse(false);
        JWTEntry jwtEntry = jwtStorageManager.getJwtsFromDB("2023", 12).get(0);
        assertEquals(jwtEntry.getExp(), 10001000);
        assertEquals(jwtEntry.getCreatedTime(), 10000100);
    }
}
