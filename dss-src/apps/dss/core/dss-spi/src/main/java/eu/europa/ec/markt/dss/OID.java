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

package eu.europa.ec.markt.dss;

public enum OID {

    // Certificate:
    /**
     * id-kp-OCSPSigning Indicates that a X.509 Certificates corresponding private key may be used by an authority to
     * sign OCSP-Responses
     */
    _1_3_6_1_5_5_7_3_9("1.3.6.1.5.5.7.3.9"),

    /**
     * id-pkix-ocsp-nocheck<br>
     * Revocation Checking of an Authorised Responder.<br>
     * An OCSP client can trust a responder for the lifetime of the responder's certificate.
     */
    _1_3_6_1_5_5_7_48_1_5("1.3.6.1.5.5.7.48.1.5"),

    /**
     *
     */
    _2_5_29_37("2.5.29.37"),

    /**
     * The CRL extension expiredCertOnCRL.
     */
    _2_5_29_60("2.5.29.60"),

    /**
     * A certificate policy for qualified certificates issued to the public.<br />
     * {itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(1456) policy-identifiers(1) qcp-public(2)}
     */
    _0_4_0_1456_1_2("0.4.0.1456.1.2"),

    /**
     * A certificate policy for qualified certificates issued to the public, requiring use of secure signature-creation devices.<br />
     * {itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(1456) policy-identifiers(1) qcp-public-with-sscd(1)}
     */
    _0_4_0_1456_1_1("0.4.0.1456.1.1");

    final String oid;

    OID(String oid) {

        this.oid = oid;
    }

    public String getName() {

        return oid;
    }
}
