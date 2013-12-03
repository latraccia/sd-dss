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

package eu.europa.ec.markt.dss.validation;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;

/**
 * 
 * Possible source of a revocation data.
 * 
 *
 * @version $Revision: 1294 $ - $Date: 2012-08-23 10:58:18 +0200 (jeu., 23 août 2012) $
 */
@XmlEnum
public enum ValidatorSourceType {
    @XmlEnumValue("CRL")
    CRL, 
    @XmlEnumValue("OCSP")
    OCSP, 
    @XmlEnumValue("TRUSTED_LIST")
    TRUSTED_LIST, 
    @XmlEnumValue("SELF_SIGNED")
    SELF_SIGNED

}
