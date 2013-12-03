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

import eu.europa.ec.markt.dss.validation.report.SignatureLevelC;

/**
 * Wrap data of a SignatureLevelC.  Used to expose the information in the Webservice.
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSSignatureLevelC {

    private String levelReached;
    private String certificateRefsVerification;
    private String revocationRefsVerification;

    /**
     * The default constructor for WSSignatureLevelC.
     */
    public WSSignatureLevelC() {
    }

    /**
     * 
     * The default constructor for WSSignatureLevelC.
     * 
     * @param level
     */
    public WSSignatureLevelC(SignatureLevelC level) {
        if (level.getLevelReached() != null) {
            levelReached = level.getLevelReached().getStatus().toString();
        }
        if (level.getCertificateRefsVerification() != null) {
            certificateRefsVerification = level.getCertificateRefsVerification().getStatus().toString();
        }
        if (level.getRevocationRefsVerification() != null) {
            revocationRefsVerification = level.getRevocationRefsVerification().getStatus().toString();
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
     * @return the certificateRefsVerification
     */
    public String getCertificateRefsVerification() {
        return certificateRefsVerification;
    }

    /**
     * @param certificateRefsVerification the certificateRefsVerification to set
     */
    public void setCertificateRefsVerification(String certificateRefsVerification) {
        this.certificateRefsVerification = certificateRefsVerification;
    }

    /**
     * @return the revocationRefsVerification
     */
    public String getRevocationRefsVerification() {
        return revocationRefsVerification;
    }

    /**
     * @param revocationRefsVerification the revocationRefsVerification to set
     */
    public void setRevocationRefsVerification(String revocationRefsVerification) {
        this.revocationRefsVerification = revocationRefsVerification;
    }

}
