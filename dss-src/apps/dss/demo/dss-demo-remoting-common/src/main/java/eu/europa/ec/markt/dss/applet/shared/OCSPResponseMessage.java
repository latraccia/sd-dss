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
 * Contains the retrieved OCSPResponse
 *  
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (lun., 06 juin 2011) $
 */

public class OCSPResponseMessage implements Serializable {

    private static final long serialVersionUID = 1L;

    private byte[] ocspResponse;

    /**
     * Get the OCSP Response
     * @return
     */
    public byte[] getOcspResponse() {
        return ocspResponse;
    }

    /**
     * Set the OCSP response
     * @param ocspResponse
     */
    public void setOcspResponse(byte[] ocspResponse) {
        this.ocspResponse = ocspResponse;
    }
    
}
