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

/**
 * Constants are listed here.
 */
public class Constants {

    public static final String OAUTH_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final String OAUTH_JWT_ASSERTION = "client_assertion";
    public static final String OAUTH_JWT_ASSERTION_TYPE = "client_assertion_type";
    public static final int DEFAULT_VALIDITY_PERIOD_IN_MINUTES = 300;
    public static final String DEFAULT_AUDIENCE = "";
    public static final boolean DEFAULT_ENABLE_JTI_CACHE = true;
    public static final String UTC = "UTC";
    public static final String TOKEN_ENDPOINT_ALIAS = "TokenEndpointAlias";
    public static final String PREVENT_TOKEN_REUSE = "PreventTokenReuse";
    public static final String REJECT_BEFORE_IN_MINUTES = "RejectBeforeInMinutes";
    public static final String ISSUER = "Issuer";
    public static final String JWT_ID_CLAIM = "jti";
    public static final String EXPIRATION_TIME_CLAIM = "exp";
    public static final String AUDIENCE_CLAIM = "aud";
    public static final String SUBJECT_CLAIM = "sub";
    public static final String ISSUER_CLAIM = "iss";
    public static final String PRIVATE_KEY_JWT = "signedJWT";
    public static final String JWKS_URI = "jwksURI";
    public static final String AUTHENTICATOR_TYPE_PARAM = "authenticatorType";
    public static final String AUTHENTICATOR_TYPE_PK_JWT = "pkJWT";
    public static final String OAUTH2_PAR_URL_REF = "OAuth2ParEPUrl";
    public static final String OAUTH2_PAR_URL_CONFIG = "OAuth.OAuth2ParEPUrl";
    public static final String FAPI2 = "2";

    //query keys
    public static final String GET_JWT_ID = "GET_JWT_ID";
    public static final String GET_JWT = "GET_JWT";
    public static final String GET_JWT_DETAILS = "GET_JWT_DETAILS";
    public static final String UPSERT_MYSQL = "UPSERT_MYSQL";
    public static final String UPSERT_H2 = "UPSERT_H2";
    public static final String UPSERT_POSTGRESQL = "UPSERT_POSTGRESQL";
    public static final String UPSERT_ORACLE = "UPSERT_ORACLE";
    public static final String UPSERT_MSSQL_DB2 = "UPSERT_MSSQL_DB2";
    public static final String INSERT_JWD_ID = "INSERT_JWD_ID";
    public static final int DEFAULT_TENANT_ID = -1;

    /**
     * SQL Queries for the JWT handler.
     */
    public static class SQLQueries {

        public static final String TENANT_ID = "TENANT_ID";
        public static final String IDN_OIDC_JTI = "IDN_OIDC_JTI";

        public static final String EXP_TIME = "EXP_TIME";
        public static final String TIME_CREATED = "TIME_CREATED";

        public static final String GET_JWT_ID = "SELECT 1 FROM IDN_OIDC_JTI WHERE JWT_ID =?";

        public static final String GET_TENANTED_JWT_ID = "SELECT 1 FROM IDN_OIDC_JTI WHERE JWT_ID =? AND TENANT_ID=?";

        public static final String GET_JWT = "SELECT EXP_TIME,TIME_CREATED FROM IDN_OIDC_JTI WHERE JWT_ID =?";
        public static final String GET_TENANTED_JWT = "SELECT EXP_TIME,TIME_CREATED FROM IDN_OIDC_JTI " +
                "WHERE JWT_ID =? AND TENANT_ID=?";

        public static final String GET_JWT_DETAIL = "SELECT TENANT_ID, EXP_TIME,TIME_CREATED FROM IDN_OIDC_JTI WHERE " +
                "JWT_ID =? AND TENANT_ID IN (?,?)";

        public static final String INSERT_JWD_ID = "INSERT INTO IDN_OIDC_JTI (JWT_ID, EXP_TIME, TIME_CREATED)" +
                "VALUES (?,?,?)";
        public static final String INSERT_TENANTED_JWD_ID = "INSERT INTO IDN_OIDC_JTI (JWT_ID, TENANT_ID, EXP_TIME, " +
                "TIME_CREATED) VALUES (?,?,?,?)";
        public static final String INSERT_OR_UPDATE_JWT_ID_MSSQL_OR_DB2 = "MERGE INTO IDN_OIDC_JTI T USING  " +
                "(VALUES (?,?,?)) S (JWT_ID, EXP_TIME, TIME_CREATED) ON T.JWT_ID = S.JWT_ID WHEN MATCHED THEN " +
                "UPDATE SET EXP_TIME = S.EXP_TIME, TIME_CREATED = S.TIME_CREATED WHEN NOT MATCHED THEN " +
                "INSERT (JWT_ID, EXP_TIME, TIME_CREATED) VALUES (S.JWT_ID, S.EXP_TIME,S.TIME_CREATED);";
        public static final String INSERT_OR_UPDATE_TENANTED_JWT_ID_MSSQL_OR_DB2 = "MERGE INTO IDN_OIDC_JTI T USING " +
                "(VALUES (?,?,?,?)) S (JWT_ID, TENANT_ID, EXP_TIME, TIME_CREATED) ON T.JWT_ID = S.JWT_ID AND " +
                "T.TENANT_ID  = S.TENANT_ID WHEN MATCHED THEN UPDATE SET EXP_TIME = S.EXP_TIME, " +
                "TIME_CREATED = S.TIME_CREATED WHEN NOT MATCHED THEN INSERT (JWT_ID, TENANT_ID, EXP_TIME, " +
                "TIME_CREATED) VALUES (S.JWT_ID, S.TENANT_ID, S.EXP_TIME,S.TIME_CREATED);";

        public static final String INSERT_OR_UPDATE_JWT_ID_MYSQL = "INSERT INTO IDN_OIDC_JTI " +
                "(JWT_ID, EXP_TIME, TIME_CREATED) VALUES (?, ?, ?)  " +
                "ON DUPLICATE KEY UPDATE EXP_TIME = VALUES(EXP_TIME), " +
                "TIME_CREATED = VALUES(TIME_CREATED)";
        public static final String INSERT_OR_UPDATE_TENANTED_JWT_ID_MYSQL = "INSERT INTO IDN_OIDC_JTI " +
                "(JWT_ID, TENANT_ID, EXP_TIME, TIME_CREATED) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE " +
                "EXP_TIME = VALUES(EXP_TIME),TIME_CREATED = VALUES(TIME_CREATED);";

        public static final String INSERT_OR_UPDATE_JWT_ID_H2 = "MERGE INTO IDN_OIDC_JTI KEY (JWT_ID) " +
                "VALUES (?, ?, ?)";

        public static final String INSERT_OR_UPDATE_TENANTED_JWT_ID_H2 = "MERGE INTO IDN_OIDC_JTI KEY " +
                "(JWT_ID, TENANT_ID) VALUES (?, ?, ?, ?)";

        public static final String INSERT_OR_UPDATE_JWT_ID_POSTGRESQL =
                "INSERT INTO IDN_OIDC_JTI (JWT_ID, EXP_TIME, TIME_CREATED) VALUES (?, ?, ?) " +
                        "ON CONFLICT (JWT_ID) DO UPDATE SET EXP_TIME = EXCLUDED.EXP_TIME, " +
                        "TIME_CREATED = EXCLUDED.TIME_CREATED";

        public static final String INSERT_OR_UPDATE_TENANTED_JWT_ID_POSTGRESQL =
                "INSERT INTO IDN_OIDC_JTI (JWT_ID, TENANT_ID, EXP_TIME, TIME_CREATED) VALUES (?,?,?,?) ON CONFLICT " +
                        "(JWT_ID,TENANT_ID) DO UPDATE SET EXP_TIME = EXCLUDED.EXP_TIME, " +
                        "TIME_CREATED = EXCLUDED.TIME_CREATED;";

        public static final String INSERT_OR_UPDATE_JWT_ID_ORACLE = "MERGE INTO IDN_OIDC_JTI USING dual ON " +
                "(JWT_ID = ?) " +
                "WHEN MATCHED THEN UPDATE SET EXP_TIME = ? , TIME_CREATED = ? " +
                "WHEN NOT MATCHED THEN INSERT (JWT_ID, EXP_TIME, TIME_CREATED) " +
                " VALUES (?, ?, ?)";
        public static final String INSERT_OR_UPDATE_TENANTED_JWT_ID_ORACLE = "MERGE INTO IDN_OIDC_JTI USING dual " +
                "ON (JWT_ID = ? AND TENANT_ID = ?) " +
                "WHEN MATCHED THEN UPDATE SET " +
                "EXP_TIME = ? , " +
                "TIME_CREATED = ? WHEN NOT MATCHED THEN INSERT (JWT_ID, TENANT_ID ,EXP_TIME, TIME_CREATED) " +
                "VALUES (?,?,?,?)";
    }
}
