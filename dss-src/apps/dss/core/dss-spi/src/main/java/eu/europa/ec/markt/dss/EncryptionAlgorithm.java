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

import java.util.HashMap;
import java.util.Map;

import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * Supported signature encryption algorithms.
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public enum EncryptionAlgorithm {

    RSA("RSA", "1.2.840.113549.1.1.1", "RSA/ECB/PKCS1Padding"), DSA("DSA", "1.2.840.10040.4.1", "DSA"), ECDSA("ECDSA", "1.2.840.10045.2.1",
          "ECDSA"), HMAC("HMAC", "", "");

    private String name;
    private String oid;
    private String padding;

    private static class Registry {

        private static final Map<String, EncryptionAlgorithm> OID_ALGORITHMS = registerOIDAlgorithms();

        private static Map<String, EncryptionAlgorithm> registerOIDAlgorithms() {

            Map<String, EncryptionAlgorithm> map = new HashMap<String, EncryptionAlgorithm>();

            for (EncryptionAlgorithm encryptionAlgo : values()) {
                map.put(encryptionAlgo.oid, encryptionAlgo);
            }
            return map;
        }
    }

    /**
     * Returns the encryption algorithm associated to the given OID.
     *
     * @param oid
     * @return
     */
    public static EncryptionAlgorithm forOID(String oid) {
        EncryptionAlgorithm algorithm = Registry.OID_ALGORITHMS.get(oid);
        if (algorithm == null) {
            throw new RuntimeException("Unsupported algorithm: " + oid);
        }
        return algorithm;
    }

    /**
     * Returns the encryption algorithm associated to the given OID.
     *
     * @param name
     * @return
     */
    public static EncryptionAlgorithm forName(String name) {

        // To be checked if ECC exists also .
        if ("EC".equals(name) || "ECC".equals(name)) {
            return ECDSA;
        }
        try {

            return valueOf(name);
        } catch (Exception e) {
        }
        throw new DSSException("Unsupported algorithm: " + name);
    }

    private EncryptionAlgorithm(String name, String oid, String padding) {
        this.name = name;
        this.oid = oid;
        this.padding = padding;
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the OID
     */
    public String getOid() {
        return oid;
    }

    /**
     * @return the padding
     */
    public String getPadding() {
        return padding;
    }
}
