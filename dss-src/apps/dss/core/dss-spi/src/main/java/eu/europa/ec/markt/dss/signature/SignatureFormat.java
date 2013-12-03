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

package eu.europa.ec.markt.dss.signature;

/**
 * Signature format handled by the application
 * 
 *
 * @version $Revision: 1128 $ - $Date: 2011-11-28 10:56:12 +0100 (Mon, 28 Nov 2011) $
 */

public enum SignatureFormat {

    XAdES_BES, XAdES_EPES, XAdES_T, XAdES_C, XAdES_X, XAdES_XL, XAdES_A,

    CAdES_BES, CAdES_EPES, CAdES_T, CAdES_C, CAdES_X, CAdES_XL, CAdES_A,

    PAdES_BES, PAdES_EPES, PAdES_LTV, 
    
    ASiC_S_BES, ASiC_S_EPES, ASiC_S_T;

    /**
     * Return the SignatureFormat based on the name (String)
     * 
     * @param name
     * @return
     */
    public static SignatureFormat valueByName(String name) {
        return valueOf(name.replace("-", "_"));
    }

    @Override
    public String toString() {
        return super.toString().replace("_", "-");
    }
    
}
