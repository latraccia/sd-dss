INSERT INTO PREFERENCES (PREF_KEY , PREF_VALUE) values ( 'preference.url.service', 'http://localhost:8080/dss-webapp/service');
INSERT INTO PREFERENCES (PREF_KEY , PREF_VALUE) values ( 'preference.default.policy.url', null);
INSERT INTO PROXY_PREFERENCES (PROXY_KEY , PROXY_VALUE) values ( 'proxy.http.host', '127.0.0.1');
INSERT INTO PROXY_PREFERENCES (PROXY_KEY , PROXY_VALUE) values ( 'proxy.http.port', '8008');
INSERT INTO PROXY_PREFERENCES (PROXY_KEY , PROXY_VALUE) values ( 'proxy.http.user', '');
INSERT INTO PROXY_PREFERENCES (PROXY_KEY , PROXY_VALUE) values ( 'proxy.http.password', '');
INSERT INTO PROXY_PREFERENCES (PROXY_KEY , PROXY_VALUE) values ( 'proxy.http.enabled', 'false');
INSERT INTO PROXY_PREFERENCES (PROXY_KEY , PROXY_VALUE) values ( 'proxy.https.host', '127.0.0.1');
INSERT INTO PROXY_PREFERENCES (PROXY_KEY , PROXY_VALUE) values ( 'proxy.https.port', '8008');
INSERT INTO PROXY_PREFERENCES (PROXY_KEY , PROXY_VALUE) values ( 'proxy.https.user', '');
INSERT INTO PROXY_PREFERENCES (PROXY_KEY , PROXY_VALUE) values ( 'proxy.https.password', '');
INSERT INTO PROXY_PREFERENCES (PROXY_KEY , PROXY_VALUE) values ( 'proxy.https.enabled', 'false');
INSERT INTO POLICIES (POLICY_KEY  , POLICY_LEVEL) values ( 'eu.europa.ec.markt.dss.checks.policy.LinkedLOTLChecker', 'YELLOW');
INSERT INTO POLICIES (POLICY_KEY  , POLICY_LEVEL) values ( 'eu.europa.ec.markt.dss.checks.policy.ProducedWithSSCDChecker', 'RED');
INSERT INTO POLICIES (POLICY_KEY  , POLICY_LEVEL) values ( 'eu.europa.ec.markt.dss.checks.policy.QualifiedCertificateChecker', 'YELLOW');
INSERT INTO POLICIES (POLICY_KEY  , POLICY_LEVEL) values ( 'eu.europa.ec.markt.dss.checks.policy.RevocationInformationChecker', 'RED');
INSERT INTO POLICIES (POLICY_KEY  , POLICY_LEVEL) values ( 'eu.europa.ec.markt.dss.checks.policy.TSLDownloadChecker', 'YELLOW');
INSERT INTO CONSTRAINTS(CONSTRAINT_TYPE, CONSTRAINT_DIGEST, CONSTRAINT_SIGNATURE, CONSTRAINT_KEY_LENGTH) values('VALIDATION' , 'SHA1','ECDSA_SHA1', 10);
INSERT INTO CONSTRAINTS(CONSTRAINT_TYPE, CONSTRAINT_DIGEST, CONSTRAINT_SIGNATURE, CONSTRAINT_KEY_LENGTH) values('SIGNATURE' , 'SHA512','RSA', 20);
