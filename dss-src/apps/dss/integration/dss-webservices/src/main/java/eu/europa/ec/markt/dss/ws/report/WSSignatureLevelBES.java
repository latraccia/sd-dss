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

package eu.europa.ec.markt.dss.ws.report;

import eu.europa.ec.markt.dss.validation.report.SignatureLevelBES;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Wrap data of a SignatureLevelBES. Used to expose the information in the Webservice.
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSSignatureLevelBES {

    private String levelReached;
    private String signingCertRefVerification;
    private List<byte[]> certificates;
    private byte[] signingCertificate;

    /**
     * The default constructor for WSSignatureLevelBES.
     */
    public WSSignatureLevelBES() {
    }

    /**
     * 
     * The default constructor for WSSignatureLevelBES.
     * 
     * @param level
     */
    public WSSignatureLevelBES(SignatureLevelBES level) {
        if (level.getLevelReached() != null) {
            levelReached = level.getLevelReached().getStatus().toString();
        }
        if (level.getSigningCertRefVerification() != null) {
            signingCertRefVerification = level.getSigningCertRefVerification().getStatus().toString();
        }
        try {
            if (level.getSigningCertificate() != null) {
                signingCertificate = level.getSigningCertificate().getEncoded();
            }
            certificates = new ArrayList<byte[]>();
            if (level.getCertificates() != null) {
                for (X509Certificate cert : level.getCertificates()) {
                    certificates.add(cert.getEncoded());
                }
            }
        } catch (CertificateEncodingException e) {
            // Should never happen
            throw new RuntimeException(e);
        }
    }

    /**
     * @return the levelReached
     */
    public String getLevelReached() {
        return levelReached;
    }

    /**
     * @param levelReached the levelReached to set
     */
    public void setLevelReached(String levelReached) {
        this.levelReached = levelReached;
    }

    /**
     * @return the signingCertRefVerification
     */
    public String getSigningCertRefVerification() {
        return signingCertRefVerification;
    }

    /**
     * @param signingCertRefVerification the signingCertRefVerification to set
     */
    public void setSigningCertRefVerification(String signingCertRefVerification) {
        this.signingCertRefVerification = signingCertRefVerification;
    }

    /**
     * @return the certificates
     */
    public List<byte[]> getCertificates() {
        return certificates;
    }

    /**
     * @param certificates the certificates to set
     */
    public void setCertificates(List<byte[]> certificates) {
        this.certificates = certificates;
    }

    /**
     * @return the signingCertificate
     */
    public byte[] getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * @param signingCertificate the signingCertificate to set
     */
    public void setSigningCertificate(byte[] signingCertificate) {
        this.signingCertificate = signingCertificate;
    }

}
