/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.validation.ocsp;

import java.io.IOException;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;

/**
 * Utility class used to convert OCSPResp to BasicOCSPResp
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public final class OCSPUtils {

    private OCSPUtils() {
    }

    /**
     * Convert a OCSPResp in a BasicOCSPResp
     *
     * @param ocspResp
     * @return
     */
    public static final BasicOCSPResp fromRespToBasic(OCSPResp ocspResp) {
        try {
            return (BasicOCSPResp) ocspResp.getResponseObject();
        } catch (OCSPException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Convert a BasicOCSPResp in OCSPResp (connection status is set to SUCCESSFUL).
     *
     * @param basicOCSPResp
     * @return
     */
    public static final OCSPResp fromBasicToResp(BasicOCSPResp basicOCSPResp) {

        try {

            return fromBasicToResp(basicOCSPResp.getEncoded());
        } catch (IOException e) {

            throw new RuntimeException(e);
        }
    }

    /**
     * Convert a BasicOCSPResp in OCSPResp (connection status is set to SUCCESSFUL).
     *
     * @param basicOCSPResp
     * @return
     */
    public static final OCSPResp fromBasicToResp(byte[] basicOCSPResp) {

        OCSPResponse response = new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL),
              new ResponseBytes(OCSPObjectIdentifiers.id_pkix_ocsp_basic, new DEROctetString(basicOCSPResp)));
        return new OCSPResp(response);
    }

}
