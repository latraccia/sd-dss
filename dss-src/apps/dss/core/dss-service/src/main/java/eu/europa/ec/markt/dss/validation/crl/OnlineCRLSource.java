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

package eu.europa.ec.markt.dss.validation.crl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

/**
 * Online CRL repository. This CRL repository implementation will download the CRLs from the given CRL URIs.
 * Note that for the HTTP kind of URLs you can provide dedicated data loader. If the data loader is not provided the standard load from URI is
 * provided. For FTP the standard load from URI is provided. For LDAP kind of URLs an internal implementation using apache-ldap-api is provided.
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class OnlineCRLSource implements CRLSource {

    private static final Logger LOG = Logger.getLogger(OnlineCRLSource.class.getName());

    private String preferredProtocol;

    private HTTPDataLoader dataLoader;

    /**
     * This method allows to set the preferred protocol to be used when retrieving CRL.
     *
     * @param preferredProtocol
     */
    public void setPreferredProtocol(String preferredProtocol) {

        this.preferredProtocol = preferredProtocol;
    }

    /**
     * Set the HTTPDataLoader to use for query the CRL server
     *
     * @param urlDataLoader
     */
    public void setDataLoader(HTTPDataLoader urlDataLoader) {

        this.dataLoader = urlDataLoader;
    }

    @Override
    public X509CRL findCrl(final X509Certificate cert, final X509Certificate issuerCert) throws DSSException {

        final String crlURL = getCrlUri(cert);
        LOG.info("CRL's URL for " + CertificateIdentifier.getIdAsString(cert) + " : " + crlURL);
        if (crlURL == null) {

            return null;
        }
        X509CRL x509CRL;
        boolean http = crlURL.startsWith("http://") || crlURL.startsWith("https://");
        if (dataLoader != null && http) {

            x509CRL = downloadCrlFromHTTP(crlURL);
        } else if (http || crlURL.startsWith("ftp://")) {

            x509CRL = downloadCRLFromURL(crlURL);
        } else if (crlURL.startsWith("ldap://")) {

            x509CRL = downloadCRLFromLDAP_(crlURL);
        } else {

            LOG.warning("DSS framework only supports HTTP, HTTPS, FTP and LDAP CRL's url.");
            return null;
        }
        if (x509CRL == null) {

            return null;
        }
        try {

            x509CRL.verify(issuerCert.getPublicKey());
        } catch (Exception e) {

            LOG.warning("The CRL signature is not valid!");
            return null;
        }
        // assert CRLSign KeyUsage bit
        final boolean[] keyUsage = issuerCert.getKeyUsage();
        if (keyUsage == null || (keyUsage != null && !keyUsage[6])) {

            LOG.warning("No KeyUsage extension for CRL issuing certificate!");
            return null;
        }
        return x509CRL;
    }

    private static X509CRL downloadCRLFromURL(String crlURL) throws DSSException {

        InputStream crlStream = null;
        try {

            final URL url = new URL(crlURL);
            crlStream = url.openStream();
            return DSSUtils.loadCRL(crlStream);
        } catch (Exception e) {

            LOG.warning(e.getMessage());
        } finally {
            IOUtils.closeQuietly(crlStream);
        }
        return null;
    }

    /**
     * Downloads a CRL from given LDAP url, e.g. ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
     *
     * @throws CertificateException
     * @throws CRLException
     */

    private static X509CRL downloadCRLFromLDAP_(final String ldapURL) throws DSSException {

        final Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);
        try {

            final DirContext ctx = new InitialDirContext(env);
            final Attributes attributes = ctx.getAttributes("");
            final javax.naming.directory.Attribute attribute = attributes.get("certificateRevocationList;binary");
            final byte[] val = (byte[]) attribute.get();
            if (val == null || val.length == 0) {

                throw new DSSException("Can not download CRL from: " + ldapURL);
            }
            final InputStream inStream = new ByteArrayInputStream(val);
            return DSSUtils.loadCRL(inStream);
        } catch (Exception e) {

            LOG.warning(e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Download a CRL from HTTP or HTTPS location.
     *
     * @param downloadUrl
     * @return
     */
    private X509CRL downloadCrlFromHTTP(String downloadUrl) {

        if (downloadUrl != null) {
            try {

                final InputStream input = dataLoader.get(downloadUrl);
                final X509CRL crl = DSSUtils.loadCRL(input);
                return crl;
            } catch (DSSException e) {

                LOG.warning(e.getMessage());
            }
        }
        return null;
    }

    /**
     * Gives back the CRL URI meta-data found within the given X509 certificate.
     *
     * @param certificate the X509 certificate.
     * @return the CRL URI, or <code>null</code> if the extension is not present.
     * @throws MalformedURLException
     */
    public String getCrlUri(X509Certificate certificate) throws DSSException {

        final byte[] crlDistributionPointsValue = certificate.getExtensionValue(X509Extension.cRLDistributionPoints.getId());
        if (null == crlDistributionPointsValue) {

            return null;
        }
        ASN1InputStream ais1 = null;
        ASN1InputStream ais2 = null;
        try {

            List<String> urls = new ArrayList<String>();
            final ByteArrayInputStream bais = new ByteArrayInputStream(crlDistributionPointsValue);
            ais1 = new ASN1InputStream(bais);
            final DEROctetString oct = (DEROctetString) (ais1.readObject());
            ais2 = new ASN1InputStream(oct.getOctets());
            final ASN1Sequence seq = (ASN1Sequence) ais2.readObject();
            final CRLDistPoint distPoint = CRLDistPoint.getInstance(seq);
            final DistributionPoint[] distributionPoints = distPoint.getDistributionPoints();
            for (final DistributionPoint distributionPoint : distributionPoints) {

                final DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
                if (DistributionPointName.FULL_NAME != distributionPointName.getType()) {

                    continue;
                }
                final GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
                final GeneralName[] names = generalNames.getNames();
                for (final GeneralName name : names) {

                    if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {

                        LOG.fine("Not a uniform resource identifier");
                        continue;
                    }
                    final String urlStr;
                    if (name.getDERObject() instanceof DERTaggedObject) {

                        final DERTaggedObject taggedObject = (DERTaggedObject) name.getDERObject();
                        final DERIA5String derStr = DERIA5String.getInstance(taggedObject.getObject());
                        urlStr = derStr.getString();
                    } else {

                        final DERIA5String derStr = DERIA5String.getInstance(name.getDERObject());
                        urlStr = derStr.getString();
                    }
                    urls.add(urlStr);
                }
                if (preferredProtocol != null) {

                    for (final String url : urls) {

                        if (url.startsWith(preferredProtocol)) {
                            return url;
                        }
                    }
                }
                if (urls.size() > 0) {

                    final String url = urls.get(0);
                    return url;
                }
            }
            return null;
        } catch (IOException e) {

            throw new DSSException(e);
        } finally {

            DSSUtils.closeQuietly(ais1);
            DSSUtils.closeQuietly(ais2);
        }
    }
}
