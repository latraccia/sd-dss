/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation.https;

import javax.net.ssl.X509TrustManager;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

/**
 * 
 * A TrustManager that trust every certificate
 * 
 * 
 * @version $Revision: 2319 $ - $Date: 2013-06-25 12:00:26 +0200 (mar., 25 juin 2013) $
 */
public class OptimistTrustManager implements X509TrustManager {

    private static final Logger LOG = Logger.getLogger(OptimistTrustManager.class.getName());

    /**
     * 
     * The default constructor for OptimistTrustManager.
     * 
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public OptimistTrustManager() throws NoSuchAlgorithmException, KeyStoreException {
        super();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certificates, String authType) throws CertificateException {
         // We trust every HTTPS. Because the TSL is signed, this is not a problem.
        log("checkClientTrusted", certificates, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certificates, String authType) throws CertificateException {
        // We trust every HTTPS. Because the TSL is signed, this is not a problem.
        log("checkServerTrusted", certificates, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    private void log(final String method, X509Certificate[] certificates, String authType) {
        String dn = null;
        if (certificates != null && certificates.length > 0) {
            final X509Certificate cert = certificates[0];
            if ( cert != null ) {
                dn = String.valueOf(cert.getSubjectDN());
            }
        }
        LOG.fine("Verification of " + dn);
    }

}
