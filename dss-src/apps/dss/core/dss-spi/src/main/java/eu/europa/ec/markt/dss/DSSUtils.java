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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

public final class DSSUtils {

    private static final Logger LOG = Logger.getLogger(DSSUtils.class.getName());

    public static final String CERT_BEGIN = "-----BEGIN CERTIFICATE-----\n";
    public static final String CERT_END = "-----END CERTIFICATE-----";

    private static final CertificateFactory certificateFactory;

    static {

        try {
            Security.addProvider(new BouncyCastleProvider());
            certificateFactory = CertificateFactory.getInstance("X.509", "BC");
        } catch (CertificateException e) {
            LOG.severe(e.toString());
            throw new DSSException("Platform does not support X509 certificate", e);
        } catch (NoSuchProviderException e) {
            LOG.severe(e.toString());
            throw new DSSException("Platform does not support BouncyCastle", e);
        }
    }

    /**
     * The default buffer size to use.
     */
    private static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

    /**
     * This class is an utility class and cannot be instantiated.
     */
    private DSSUtils() {
    }

    /**
     * formats a date to be used for internal purposes (logging, toString)
     *
     * @param date the date to be converted
     * @return the textual representation (a null date will result in "N/A")
     */
    public static String formatInternal(Date date) {

        return (date == null) ? "N/A" : new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(date);
    }

    /**
     * Converts a given <code>Date</code> to a new <code>XMLGregorianCalendar</code>.
     *
     * @param date the date to be converted
     * @return the new <code>XMLGregorianCalendar</code> or null
     */
    public static XMLGregorianCalendar createXMGregorianCalendar(Date date) {

        if (date == null) {
            return null;
        }

        final GregorianCalendar calendar = new GregorianCalendar();
        calendar.setTime(date);

        try {
            XMLGregorianCalendar gc = DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar);
            gc.setFractionalSecond(null);
            gc = gc.normalize(); // to UTC = Zulu
            return gc;
        } catch (DatatypeConfigurationException e) {

            // LOG.log(Level.WARNING, "Unable to properly convert a Date to an XMLGregorianCalendar",e);
        }

        return null;
    }

    /**
     * Converts an array of bytes into a String representing the hexadecimal values of each byte in order. The returned
     * String will be double the length of the passed array, as it takes two characters to represent any given byte. If
     * the input array is null then null is returned. The obtained string is converted to uppercase.
     *
     * @param value
     * @return
     */
    public static String toHex(final byte[] value) {

        return (value != null) ? new String(Hex.encodeHex(value, false)) : null;
    }

    /**
     * Decodes a Base64 String into bytes.
     *
     * @param base64String
     * @return
     */
    public static byte[] base64Decode(String base64String) {

        return Base64.decodeBase64(base64String);
    }

    /**
     * Decodes a Base64 String into bytes.
     *
     * @param binaryData
     * @return
     */
    public static byte[] base64Decode(byte[] binaryData) {

        return Base64.decodeBase64(binaryData);
    }

    /**
     * Encodes binary data using the base64 algorithm but does not chunk the output. NOTE: We changed the behaviour of
     * this method from multi-line chunking (commons-codec-1.4) to single-line non-chunking (commons-codec-1.5).
     *
     * @param binaryData
     * @return
     */
    public static String base64Encode(byte[] binaryData) {

        return Base64.encodeBase64String(binaryData);
    }

    /**
     * Unconditionally close an <code>InputStream</code>.
     * <p>
     * Equivalent to <code>InputStream.close()</code>, except any exceptions will be ignored. This is typically used in
     * finally blocks.
     *
     * @param input
     */
    public static void closeQuietly(InputStream input) {

        if (input != null) {
            try {
                input.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    /**
     * Unconditionally close an <code>OutputStream</code>.
     * <p>
     * Equivalent to {@link OutputStream#close()}, except any exceptions will be ignored. This is typically used in
     * finally blocks.
     *
     * @param output
     */
    public static void closeQuietly(OutputStream output) {

        if (output != null) {
            try {
                output.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    /**
     * Unconditionally close an <code>Reader</code>.
     * <p>
     * Equivalent to {@link Reader#close()}, except any exceptions will be ignored. This is typically used in finally
     * blocks.
     *
     * @param input the Reader to close, may be null or already closed
     */
    public static void closeQuietly(Reader input) {
        try {
            if (input != null) {
                input.close();
            }
        } catch (IOException ioe) {
            // ignore
        }
    }

    /**
     * Unconditionally close a <code>Writer</code>.
     * <p>
     * Equivalent to {@link Writer#close()}, except any exceptions will be ignored. This is typically used in finally
     * blocks.
     *
     * @param output the Writer to close, may be null or already closed
     */
    public static void closeQuietly(Writer output) {
        try {
            if (output != null) {
                output.close();
            }
        } catch (IOException ioe) {
            // ignore
        }
    }

    /**
     * Get the contents of an <code>InputStream</code> as a String using the specified character encoding.
     * <p>
     * Character encoding names can be found at <a href="http://www.iana.org/assignments/character-sets">IANA</a>.
     * <p>
     * This method buffers the input internally, so there is no need to use a <code>BufferedInputStream</code>.
     *
     * @param input    the <code>InputStream</code> to read from
     * @param encoding the encoding to use, null means platform default
     * @return the requested String
     * @throws NullPointerException if the input is null
     * @throws IOException          if an I/O error occurs
     */
    public static String toString(InputStream input, String encoding) throws IOException {
        StringWriter sw = new StringWriter();
        copy(input, sw, encoding);
        return sw.toString();
    }

    /**
     * Copy bytes from an <code>InputStream</code> to chars on a <code>Writer</code> using the specified character
     * encoding.
     * <p>
     * This method buffers the input internally, so there is no need to use a <code>BufferedInputStream</code>.
     * <p>
     * Character encoding names can be found at <a href="http://www.iana.org/assignments/character-sets">IANA</a>.
     * <p>
     * This method uses {@link InputStreamReader}.
     *
     * @param input    the <code>InputStream</code> to read from
     * @param output   the <code>Writer</code> to write to
     * @param encoding the encoding to use, null means platform default
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     * @since Commons IO 1.1
     */
    public static void copy(InputStream input, Writer output, String encoding) throws IOException {
        if (encoding == null) {
            copy(input, output);
        } else {
            InputStreamReader in = new InputStreamReader(input, encoding);
            copy(in, output);
        }
    }

    /**
     * Copy bytes from an <code>InputStream</code> to chars on a <code>Writer</code> using the default character encoding
     * of the platform.
     * <p>
     * This method buffers the input internally, so there is no need to use a <code>BufferedInputStream</code>.
     * <p>
     * This method uses {@link InputStreamReader}.
     *
     * @param input  the <code>InputStream</code> to read from
     * @param output the <code>Writer</code> to write to
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     * @since Commons IO 1.1
     */
    public static void copy(InputStream input, Writer output) throws IOException {
        InputStreamReader in = new InputStreamReader(input);
        copy(in, output);
    }

    /**
     * Copy chars from a <code>Reader</code> to a <code>Writer</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a <code>BufferedReader</code>.
     * <p>
     * Large streams (over 2GB) will return a chars copied value of <code>-1</code> after the copy has completed since
     * the correct number of chars cannot be returned as an int. For large streams use the
     * <code>copyLarge(Reader, Writer)</code> method.
     *
     * @param input  the <code>Reader</code> to read from
     * @param output the <code>Writer</code> to write to
     * @return the number of characters copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     * @throws ArithmeticException  if the character count is too large
     * @since Commons IO 1.1
     */
    public static int copy(Reader input, Writer output) throws IOException {
        long count = copyLarge(input, output);
        if (count > Integer.MAX_VALUE) {
            return -1;
        }
        return (int) count;
    }

    /**
     * Copy chars from a large (over 2GB) <code>Reader</code> to a <code>Writer</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a <code>BufferedReader</code>.
     *
     * @param input  the <code>Reader</code> to read from
     * @param output the <code>Writer</code> to write to
     * @return the number of characters copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException          if an I/O error occurs
     * @since Commons IO 1.3
     */
    public static long copyLarge(Reader input, Writer output) throws IOException {
        char[] buffer = new char[DEFAULT_BUFFER_SIZE];
        long count = 0;
        int n = 0;
        while (-1 != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
            count += n;
        }
        return count;
    }

    /**
     * This method replaces all \ to /.
     *
     * @param path
     * @return
     */
    private static String normalisePath(String path) {

        return path.replace('\\', '/');
    }

    /**
     * This method checks if the file with the given path exists.
     *
     * @param path
     * @return
     */
    public static boolean fileExists(String path) {

        path = normalisePath(path);
        URL url = DSSUtils.class.getResource(path);
        return url != null;
        // return new File(path).exists();
    }

    /**
     * This method returns a file reference. The file path is normalised (OS independent)
     *
     * @param folderFileName
     * @return
     */
    public static File getFile(final String folderFileName) {

        String normalisedFolderFileName = normalisePath(folderFileName);
        File file = new File(normalisedFolderFileName);
        return file;
    }

    /**
     * This method converts the given certificate into its PEM string.
     *
     * @param cert
     * @return
     * @throws CertificateEncodingException
     */
    public static String convertToPEM(final X509Certificate cert) throws CertificateEncodingException {

        final Base64 encoder = new Base64(64);

        final byte[] derCert = cert.getEncoded();
        final String pemCertPre = new String(encoder.encode(derCert));
        final String pemCert = CERT_BEGIN + pemCertPre + CERT_END;
        return pemCert;
    }

    /**
     * This method loads a certificate from the given resource.  The certificate must be DER-encoded and may be supplied in binary or printable
     * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and
     * must be bounded at the end by -----END CERTIFICATE-----. It throws an <code>DSSException</code> or return <code>null</code> when the
     * certificate cannot be loaded.
     *
     * @param path resource location.
     * @return
     */
    public static X509Certificate loadCertificate(String path) {

        final InputStream inputStream = DSSUtils.class.getResourceAsStream(path);
        return loadCertificate(inputStream);
    }

    /**
     * This method loads a certificate from the given location. The certificate must be DER-encoded and may be supplied in binary or printable
     * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and
     * must be bounded at the end by -----END CERTIFICATE-----. It throws an <code>DSSException</code> or return <code>null</code> when the
     * certificate cannot be loaded.
     *
     * @param inputStream input stream containing the certificate
     * @return
     */
    public static X509Certificate loadCertificate(final InputStream inputStream) {

        try {

            final X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            return cert;
        } catch (CertificateException e) {
            throw new DSSException(e);
        }
    }

    /**
     * This method loads a certificate from the byte array. The certificate must be DER-encoded and may be supplied in binary or printable
     * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and
     * must be bounded at the end by -----END CERTIFICATE-----. It throws an <code>DSSException</code> or return <code>null</code> when the
     * certificate cannot be loaded.
     *
     * @param input array of bytes containing the certificate
     * @return
     */
    public static X509Certificate loadCertificate(final byte[] input) {

        return loadCertificate(new ByteArrayInputStream(input));
    }

    /**
     * This method loads the issuer certificate from the given location (AIA).  The certificate must be DER-encoded and may be supplied in binary or
     * printable (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN
     * CERTIFICATE-----, and must be bounded at the end by -----END CERTIFICATE-----.  It throws an
     * <code>DSSException</code> or return <code>null</code> when the certificate cannot be loaded.
     *
     * @param cert   certificate for which the issuer should be loaded
     * @param loader the loader to use
     * @return
     */
    public static X509Certificate loadIssuerCertificate(final X509Certificate cert, final HTTPDataLoader loader) {

        final String url = getAccessLocation(cert, X509ObjectIdentifiers.id_ad_caIssuers);
        if (url != null) {

            try {

                InputStream inputStream = loader.get(url);
                final X509Certificate issuerCert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
                if (cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {

                    return cert;
                }
            } catch (Exception e) {

                throw new DSSException("!!! Cannot load the issuer certificate", e);
            }
        }
        return null;
    }

    /**
     * @param x509Certificate
     * @return the SKI value of the certificate. Null if no such extension
     * @throws Exception
     */
    public static byte[] getSki(X509Certificate x509Certificate) {
        try {
            final byte[] extensionValue = x509Certificate.getExtensionValue("2.5.29.14");
            if (extensionValue == null) {
                return null;
            }
            ASN1OctetString str = ASN1OctetString.getInstance(new ASN1InputStream(new ByteArrayInputStream(extensionValue)).readObject());
            SubjectKeyIdentifier keyId = SubjectKeyIdentifier
                  .getInstance(new ASN1InputStream(new ByteArrayInputStream(str.getOctets())).readObject());
            return keyId.getKeyIdentifier();
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    private static String getAccessLocation(final X509Certificate certificate, final DERObjectIdentifier accessMethod) {

        try {

            final byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(X509Extension.authorityInfoAccess.getId());
            if (null == authInfoAccessExtensionValue) {
                return null;
            }
         /* Parse the extension */
            final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(authInfoAccessExtensionValue));
            final DEROctetString oct = (DEROctetString) (asn1InputStream.readObject());
            asn1InputStream.close();
            final ASN1InputStream asn1InputStream2 = new ASN1InputStream(oct.getOctets());
            final AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
                  (ASN1Sequence) asn1InputStream2.readObject());
            asn1InputStream2.close();

            final AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
            for (final AccessDescription accessDescription : accessDescriptions) {

                // LOG.fine("access method: " + accessDescription.getAccessMethod());
                final boolean correctAccessMethod = accessDescription.getAccessMethod().equals(accessMethod);
                if (!correctAccessMethod) {
                    continue;
                }
                GeneralName gn = accessDescription.getAccessLocation();
                if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {

                    // LOG.fine("not a uniform resource identifier");
                    continue;
                }
                final DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.getDERObject()).getObject();
                final String accessLocation = str.getString();
                // LOG.fine("access location: " + accessLocation);
                return accessLocation;
            }
        } catch (final IOException e) {

            // we do nothing
            // LOG.("IO error: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * This method loads a CRL from the given base 64 encoded string.
     *
     * @param base64Encoded
     * @return
     */
    public static X509CRL loadCRLBase64Encoded(final String base64Encoded) {

        final byte[] derEncoded = DSSUtils.base64Decode(base64Encoded);
        final X509CRL crl = loadCRL(new ByteArrayInputStream(derEncoded));
        return crl;
    }

    /**
     * This method loads a CRL from the given location.
     *
     * @param byteArray
     * @return
     */
    public static X509CRL loadCRL(final byte[] byteArray) {

        final X509CRL crl = loadCRL(new ByteArrayInputStream(byteArray));
        return crl;
    }

    /**
     * This method loads a CRL from the given location.
     *
     * @param inputStream
     * @return
     */
    public static X509CRL loadCRL(final InputStream inputStream) {

        try {

            final X509CRL crl = (X509CRL) certificateFactory.generateCRL(inputStream);
            return crl;
        } catch (CRLException e) {

            throw new DSSException(e);
        }
    }

    /**
     * This method loads an OCSP response from the given base 64 encoded string.
     *
     * @param base64Encoded
     * @return
     */
    public static BasicOCSPResp loadOCSPBase64Encoded(final String base64Encoded) {

        final byte[] derEncoded = DSSUtils.base64Decode(base64Encoded);
        BasicOCSPResp basicOCSPResp = null;
        try {

            basicOCSPResp = (BasicOCSPResp) new OCSPResp(derEncoded).getResponseObject();
        } catch (OCSPException e) {
            throw new DSSException(e);
        } catch (IOException e) {
            throw new DSSException(e);
        }
        return basicOCSPResp;
    }

    public static List<String> getPolicyIdentifiers(X509Certificate cert) {

        final byte[] certificatePolicies = cert.getExtensionValue(X509Extension.certificatePolicies.getId());
        if (certificatePolicies == null) {

            return Collections.emptyList();
        }
        ASN1InputStream input = null;
        DERSequence seq = null;
        try {

            input = new ASN1InputStream(certificatePolicies);
            final DEROctetString s = (DEROctetString) input.readObject();
            final byte[] content = s.getOctets();
            input.close();
            input = new ASN1InputStream(content);
            seq = (DERSequence) input.readObject();
        } catch (IOException e) {

            throw new DSSException("Error when computing certificate's extensions.", e);
        } finally {

            DSSUtils.closeQuietly(input);
        }
        final List<String> policyIdentifiers = new ArrayList<String>();
        for (int ii = 0; ii < seq.size(); ii++) {

            final PolicyInformation policyInfo = PolicyInformation.getInstance(seq.getObjectAt(ii));
            // System.out.println("\t----> PolicyIdentifier: " + policyInfo.getPolicyIdentifier().getId());
            policyIdentifiers.add(policyInfo.getPolicyIdentifier().getId());

        }
        return policyIdentifiers;
    }

    /**
     * @param certificateTokens
     * @return a list for each certificateToken.getCertificate
     */
    public static List<X509Certificate> getX509Certificates(List<CertificateToken> certificateTokens) {
        final List<X509Certificate> certificateChain = new ArrayList<X509Certificate>();
        for (final CertificateToken token : certificateTokens) {
            certificateChain.add(token.getCertificate());
        }
        return certificateChain;

    }
}
