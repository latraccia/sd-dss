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

import javax.security.auth.x500.X500Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Utility class to check if two principals are equal
 *
 *
 * @version $Revision: 2269 $ - $Date: 2013-06-21 16:58:21 +0200 (ven., 21 juin 2013) $
 */

public class X500PrincipalMatcher {

    private static final Logger LOG = Logger.getLogger(X500PrincipalMatcher.class.getName());

    /**
     * flag to configure on VM level unescaping of \xNN encoded literals<br/>
     * to enable this, use <code>-Ddss.dn.unescapemultibyteutf8literal=true</code><br/>
     * you can set this flag also programmatically via <code>System.getProperty(...)</code> and then calling {@link #resolvePatchConfiguration()}.
     */
    public static final String DSS_DN_UNESCAPEMULTIBYTEUTF8LITERAL = "dss.dn.unescapemultibyteutf8literal";
    private static boolean APPLY_UNESCAPEMULTIBYTEUTF8LITERAL;

    static {
        resolvePatchConfiguration();
    }

    private X500PrincipalMatcher() {
        // hidden utility constructor
    }

    /**
     * checks if the two principals are equal in a somewhat relaxed way.
     *
     * @param p1 not null
     * @param p2 not null
     * @return true, if either {@link #viaEquals(javax.security.auth.x500.X500Principal, javax.security.auth.x500.X500Principal)} or {@link #viaName(javax.security.auth.x500.X500Principal, javax.security.auth.x500.X500Principal)}
     */
    public static boolean viaAny(final X500Principal p1, final X500Principal p2) {
        return viaEquals(p1, p2) || viaName(p1, p2);
    }

    /**
     * checks if the two principals are equal via the equals-method
     *
     * @param p1 not null
     * @param p2 nullable
     * @return true if {@link X500Principal#equals(Object)}
     */
    public static boolean viaEquals(final X500Principal p1, final X500Principal p2) {
        return p1.equals(p2);
    }

    /**
     * checks if the two principals are equal via the canonical names<br/>
     * note that this also unescapes python style utf literals ("\xc3\xa9" to "é")
     *
     * @param p1 not null
     * @param p2 not null
     * @return true if {@link String#equals(Object)}
     */
    public static boolean viaName(final X500Principal p1, final X500Principal p2) {
        final String cn1 = getCanonicalName(p1);
        final String n1 = maybePatchDN(cn1);
        final String cn2 = getCanonicalName(p2);
        final String n2 = maybePatchDN(cn2);
        return n1.equals(n2);
    }

    private static String getCanonicalName(final X500Principal p1) {
        return p1.getName(X500Principal.CANONICAL);
    }

    // ------------------------------------------------------------------------

    /**
     * checks if the two principals are equal in a somewhat relaxed way.
     *
     * @param p1 not null
     * @param p2 not null
     * @return true, if either {@link #viaEquals(org.bouncycastle.asn1.x500.X500Name, org.bouncycastle.asn1.x500.X500Name)}  or {@link #viaName(org.bouncycastle.asn1.x500.X500Name, org.bouncycastle.asn1.x500.X500Name)}
     */
    public static boolean viaAny(final org.bouncycastle.asn1.x500.X500Name p1, final org.bouncycastle.asn1.x500.X500Name p2) {
        return viaEquals(p1, p2) || viaName(p1, p2);
    }

    /**
     * checks if the two names are equal via the equals-method
     *
     * @param p1 not null
     * @param p2 nullable
     * @return true if {@link X500Principal#equals(Object)}
     */
    public static boolean viaEquals(final org.bouncycastle.asn1.x500.X500Name p1, final org.bouncycastle.asn1.x500.X500Name p2) {
        return p1.equals(p2);
    }

    /**
     * checks if the two principals are equal via the canonical names<br/>
     * note that this also unescapes python style utf literals ("\xc3\xa9" to "é")
     *
     * @param p1 not null
     * @param p2 not null
     * @return true if {@link String#equals(Object)}
     */
    public static boolean viaName(final org.bouncycastle.asn1.x500.X500Name p1, final org.bouncycastle.asn1.x500.X500Name p2) {
        final String cn1 = getCanonicalName(p1);
        final String n1 = maybePatchDN(cn1);
        final String cn2 = getCanonicalName(p2);
        final String n2 = maybePatchDN(cn2);
        return n1.equals(n2);
    }

    private static String getCanonicalName(final org.bouncycastle.asn1.x500.X500Name p1) {
        return p1.toString();
    }

    // ------------------------------------------------------------------------

    /**
     * this checks for {@link #DSS_DN_UNESCAPEMULTIBYTEUTF8LITERAL} that configures {@link #maybePatchDN(String)}.
     */
    public static void resolvePatchConfiguration() {
        APPLY_UNESCAPEMULTIBYTEUTF8LITERAL = "true".equalsIgnoreCase(System.getProperty(DSS_DN_UNESCAPEMULTIBYTEUTF8LITERAL, "false"));
    }

    /**
     * sets the value for {@link #DSS_DN_UNESCAPEMULTIBYTEUTF8LITERAL} so that {@link #maybePatchDN(String)} is executed in that respect.
     */
    public static void enablePatchDN() {
        System.setProperty(DSS_DN_UNESCAPEMULTIBYTEUTF8LITERAL, "true");
        resolvePatchConfiguration();
    }

    /**
     * depending on the VM configuration, the distinguished name is patched<br/>
     * e.g.: via {@link X500PrincipalMatcher#DSS_DN_UNESCAPEMULTIBYTEUTF8LITERAL} "\xc3\xa9" to "é"<br/>
     * this has been specifically introduced for french signatures that have invalid XML escapes (see http://www.jira.e-codex.eu/browse/ECDX-59)
     *
     * @param distinguishedName the text
     * @return either the original one or the patched one
     */
    public static String maybePatchDN(String distinguishedName) {
        if ( APPLY_UNESCAPEMULTIBYTEUTF8LITERAL ) {
            distinguishedName = unescapeMultiByteUtf8Literals(distinguishedName);
        }
        return distinguishedName;
    }

    /**
     * replaces e.g. "\xc3\xa9" with "é"
     *
     * @param s the input
     * @return the output
     */
    private static String unescapeMultiByteUtf8Literals(final String s) {
        try {
            final String q = new String(unescapePython(s.getBytes("UTF-8")), "UTF-8");
            if (!q.equals(s)) {
                LOG.log(Level.SEVERE, "multi byte utf literal found:\n" +
                    "  orig = " + s + "\n" +
                    "  escp = " + q
                );
            }
            return q;
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Could not unescape multi byte utf literal - will use original input: " + s, e);
            return s;
        }
    }

    private static byte[] unescapePython(final byte[] escaped) throws Exception {
        // simple state machine iterates over the escaped bytes and converts
        final byte[] unescaped = new byte[escaped.length];
        int posTarget = 0;
        for ( int posSource = 0; posSource < escaped.length; posSource++ ) {
            // if its not special then just move on
            if ( escaped[posSource] != '\\' ) {
                unescaped[posTarget] = escaped[posSource];
                posTarget++;
                continue;
            }
            // if there is no next byte, throw incorrect encoding error
            if ( posSource + 1 >= escaped.length ) {
                throw new Exception("String incorrectly escaped, ends with escape character.");
            }
            // deal with hex first
            if ( escaped[posSource + 1] == 'x' ) {
                // if there's no next byte, throw incorrect encoding error
                if ( posSource + 3 >= escaped.length ) {
                    throw new Exception("String incorrectly escaped, ends early with incorrect hex encoding.");
                }
                unescaped[posTarget] = (byte) ( ( Character.digit(escaped[posSource + 2], 16) << 4 ) + Character.digit(escaped[posSource + 3], 16) );
                posTarget++;
                posSource += 3;
            }
            // deal with n, then t, then r
            else if ( escaped[posSource + 1] == 'n' ) {
                unescaped[posTarget] = '\n';
                posTarget++;
                posSource++;
            } else if ( escaped[posSource + 1] == 't' ) {
                unescaped[posTarget] = '\t';
                posTarget++;
                posSource++;
            } else if ( escaped[posSource + 1] == 'r' ) {
                unescaped[posTarget] = '\r';
                posTarget++;
                posSource++;
            } else if ( escaped[posSource + 1] == '\\' ) {
                unescaped[posTarget] = escaped[posSource + 1];
                posTarget++;
                posSource++;
            } else if ( escaped[posSource + 1] == '\'' ) {
                unescaped[posTarget] = escaped[posSource + 1];
                posTarget++;
                posSource++;
            } else {
                // invalid character
                throw new Exception("String incorrectly escaped, invalid escaped character");
            }
        }
        final byte[] result = new byte[posTarget];
        System.arraycopy(unescaped, 0, result, 0, posTarget);
        // return byte array, not string. Callers can convert to string.
        return result;
    }

}