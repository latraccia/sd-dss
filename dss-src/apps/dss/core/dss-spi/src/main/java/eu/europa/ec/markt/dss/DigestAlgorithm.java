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

import javax.xml.crypto.dsig.DigestMethod;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Supported Algorithms
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */
public enum DigestAlgorithm {

    // see DEPRECATED http://www.w3.org/TR/2012/WD-xmlsec-algorithms-20120105/
    // see http://www.w3.org/TR/2013/NOTE-xmlsec-algorithms-20130411/
    //@formatter:off
    SHA1("SHA-1", "1.3.14.3.2.26", DigestMethod.SHA1),
    SHA224("SHA-224", "2.16.840.1.101.3.4.2.4", "http://www.w3.org/2001/04/xmldsig-more#sha224"),
    SHA256("SHA-256", "2.16.840.1.101.3.4.2.1", DigestMethod.SHA256),
    SHA384("SHA-384", "2.16.840.1.101.3.4.2.2", "http://www.w3.org/2001/04/xmldsig-more#sha384"),
    SHA512("SHA-512", "2.16.840.1.101.3.4.2.3", DigestMethod.SHA512),
    RIPEMD160("RIPEMD-160", "1.3.36.3.2.1", DigestMethod.RIPEMD160),
    MD2("MD2", "1.2.840.113549.1.1.2", "http://www.w3.org/2001/04/xmldsig-more#md2"),
    MD5("MD5", "1.2.840.113549.2.5", "http://www.w3.org/2001/04/xmldsig-more#md5");
    /**
     * RFC 2313
     * "MD2", "1.2.840.113549.2.2"
     * "MD4", "1.2.840.113549.2.4"
     * "MD5", "1.2.840.113549.2.5"
     */
    //@formatter:on

    private String name;
    private String oid;
    private String xmlId;

    private static class Registry {

        private final static Map<String, DigestAlgorithm> OID_ALGORITHMS = registerOIDAlgorithms();
        private final static Map<String, DigestAlgorithm> XML_ALGORITHMS = registerXMLAlgorithms();
        private final static Map<String, DigestAlgorithm> ALGORITHMS = registerAlgorithms();

        private static Map<String, DigestAlgorithm> registerOIDAlgorithms() {
            final Map<String, DigestAlgorithm> map = new HashMap<String, DigestAlgorithm>();

            for (DigestAlgorithm digestAlgo : values()) {
                map.put(digestAlgo.oid, digestAlgo);
            }

            return map;
        }

        private static Map<String, DigestAlgorithm> registerXMLAlgorithms() {
            final Map<String, DigestAlgorithm> map = new HashMap<String, DigestAlgorithm>();

            for (DigestAlgorithm digestAlgo : values()) {
                map.put(digestAlgo.xmlId, digestAlgo);
            }

            return map;
        }

        private static Map<String, DigestAlgorithm> registerAlgorithms() {
            final Map<String, DigestAlgorithm> map = new HashMap<String, DigestAlgorithm>();

            for (DigestAlgorithm digestAlgo : values()) {
                map.put(digestAlgo.name, digestAlgo);
            }

            return map;
        }
    }

    /**
     * Returns the digest algorithm associated to the given OID.
     *
     * @param name
     * @return
     */
    public static DigestAlgorithm forName(String name) {
        DigestAlgorithm algorithm = Registry.ALGORITHMS.get(name);
        if (algorithm == null) {
            throw new RuntimeException("Unsupported algorithm: " + name);
        }
        return algorithm;
    }

    /**
     * Returns the digest algorithm associated to the given OID.
     *
     * @param oid
     * @return
     */
    public static DigestAlgorithm forOID(String oid) {
        DigestAlgorithm algorithm = Registry.OID_ALGORITHMS.get(oid);
        if (algorithm == null) {
            throw new RuntimeException("Unsupported algorithm: " + oid);
        }
        return algorithm;
    }

    /**
     * Returns the digest algorithm associated to the given XML url.
     *
     * @param xmlName
     * @return
     */
    public static DigestAlgorithm forXML(String xmlName) {
        DigestAlgorithm algorithm = Registry.XML_ALGORITHMS.get(xmlName);
        if (algorithm == null) {
            throw new RuntimeException("Unsupported algorithm: " + xmlName);
        }
        return algorithm;
    }

    private DigestAlgorithm(String name, String oid, String xmlId) {
        this.name = name;
        this.oid = oid;
        this.xmlId = xmlId;
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
     * @return the xmlId
     */
    public String getXmlId() {
        return xmlId;
    }

    /**
     * Gets the ASN.1 algorithm identifier structure corresponding to this digest algorithm
     *
     * @return the AlgorithmIdentifier
     */
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        /*
		 * The recommendation (cf. RFC 3380 section 2.1) is to omit the parameter for SHA-1, but some implementations still expect a
		 * NULL there. Therefore we always include a NULL parameter even with SHA-1, despite the recommendation, because the RFC
		 * states that implementations SHOULD support it as well anyway
		 */
        return new AlgorithmIdentifier(new DERObjectIdentifier(this.getOid()), new DERNull());
    }
}
