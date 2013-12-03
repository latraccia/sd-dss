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

package eu.europa.ec.markt.dss.applet.shared;

import java.io.Serializable;

/**
 * Contains an array of every potential issuers corresponding to a X500Principal
 *
 * @version $Revision: 2910 $ - $Date: 2013-11-08 15:18:08 +0100 (ven., 08 nov. 2013) $
 */

public class PotentialIssuerResponseMessage implements Serializable {

    private static final long serialVersionUID = 1L;

    private byte[][] potentialIssuer;

    private String[][] source;

    private Serializable[][] serviceInfo;

    /**
     * Get the array of X509Certificate for each potential issuer
     *
     * @return
     */
    public byte[][] getPotentialIssuer() {
        return potentialIssuer;
    }

    /**
     * Set the array of X509Certificate that contains all the potential issuers.
     *
     * @param potentialIssuer
     */
    public void setPotentialIssuer(final byte[][] potentialIssuer) {
        this.potentialIssuer = potentialIssuer;
    }

    /**
     * Get the array of source for each potential issuer
     *
     * @return
     */
    public String[][] getSource() {
        return source;
    }

    /**
     * Set the array of source for each potential issuer
     *
     * @param certificateSource
     */
    public void setSource(final String[][] certificateSource) {
        this.source = certificateSource;
    }

    /**
     * Get information about the context from which the certificate is fetched (Trusted Service info with qualification elements).
     *
     * @return
     */
    public Serializable[][] getServiceInfo() {
        return serviceInfo;
    }

    /**
     * Set information about the context from which the certificate is fetched
     *
     * @param serviceInfo
     */
    public void setServiceInfo(final Serializable[][] serviceInfo) {
        this.serviceInfo = serviceInfo;
    }
}
