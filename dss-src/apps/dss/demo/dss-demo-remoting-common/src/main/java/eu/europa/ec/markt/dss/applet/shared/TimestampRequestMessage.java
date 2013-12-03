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
 * Contains the information needed to create a TimeStamp.
 * 
 *
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class TimestampRequestMessage implements Serializable {

    private static final long serialVersionUID = 1L;

    private String algorithm;

    private byte[] digest;

    /**
     * Get algorithm used for digest creation
     * 
     * @return
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Set algorithm used for digest creation
     * 
     * @param algorithm
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Get digest value
     * 
     * @return
     */
    public byte[] getDigest() {
        return digest;
    }

    /**
     * Set digest value
     * 
     * @param digest
     */
    public void setDigest(byte[] digest) {
        this.digest = digest;
    }

}
