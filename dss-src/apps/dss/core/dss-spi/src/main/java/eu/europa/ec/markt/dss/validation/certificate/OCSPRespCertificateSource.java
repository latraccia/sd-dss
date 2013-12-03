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

package eu.europa.ec.markt.dss.validation.certificate;

import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;

import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.EncodingException.MSG;

/**
 * Implement a CertificateSource that retrieve the certificates from an OCSPResponse
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class OCSPRespCertificateSource extends OfflineCertificateSource {

    private static final Logger LOG = Logger.getLogger(OCSPRespCertificateSource.class.getName());

    private BasicOCSPResp ocspResp;

    /**
     * The default constructor for OCSPRespCertificateSource.
     */
    public OCSPRespCertificateSource(BasicOCSPResp ocspResp) {
        this.ocspResp = ocspResp;
    }

    @Override
    public List<X509Certificate> getCertificates() {
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        try {

            for (X509Certificate c : ocspResp.getCerts(null)) {
                LOG.fine(c.getSubjectX500Principal() + " issued by " + c.getIssuerX500Principal() + " serial number " + c.getSerialNumber());
                certs.add(c);
            }
        } catch (OCSPException ex) {
            throw new EncodingException(MSG.OCSP_CANNOT_BE_READ);
        } catch (NoSuchProviderException e) {
            // Provider (BouncyCastle) not found. Should never happens.
            throw new RuntimeException(e);
        }
        return certs;
    }

}
