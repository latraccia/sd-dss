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

/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/branches/DSS-3.0/apps/dss/core/dss-spi/src/main/java/eu/europa/ec/markt/dss/signature/MimeType.java $
 * $Revision: 2922 $
 * $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 * $Author: bielecro $
 */
package eu.europa.ec.markt.dss.signature;

/**
 * TODO
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public enum MimeType {

    BINARY("application/octet-stream"), XML("text/xml"), PDF("application/pdf"), PKCS7("application/pkcs7-signature"), ASICS(
            "application/vnd.etsi.asic-s+zip");

    private String code;

    /**
     * The default constructor for MimeTypes.
     */
    private MimeType(String code) {
        this.code = code;
    }

    /**
     * @return the code
     */
    public String getCode() {
        return code;
    }

    public static MimeType fromFileName(String name) {
        if (name.toLowerCase().endsWith(".xml")) {
            return XML;
        } else if (name.toLowerCase().endsWith(".pdf")) {
            return PDF;
        } else {
            return BINARY;
        }
    }

}
