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

package eu.europa.ec.markt.dss.validation102853.tsl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullReturnedException;
import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CommonTrustedCertificateSource;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * Certificate coming from the Trusted List
 *
 * @version $Revision: 1845 $ - $Date: 2013-04-04 17:46:25 +0200 (Thu, 04 Apr 2013) $
 */

public class TrustedListsCertificateSource extends CommonTrustedCertificateSource {

    private static final Logger LOG = Logger.getLogger(TrustedListsCertificateSource.class.getName());

    // prefix of a resource to be found on the classpath - Spring notation
    private static final String CP = "classpath://";
    private static final String FILE = "file://";

    protected String lotlUrl;

    protected transient HTTPDataLoader dataLoader;

    private Map<String, String> diagnosticInfo = new HashMap<String, String>();

    /**
     * Defines if the TL signature must be checked. The default value is true.
     */
    protected boolean checkSignature = true;

    protected String lotlCertificate;

    static {

        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * The default constructor.
     */
    public TrustedListsCertificateSource() {
        super();
    }

    /**
     * The copy constructor.
     *
     * @param trustedListsCertificateSource
     */
    public TrustedListsCertificateSource(final TrustedListsCertificateSource trustedListsCertificateSource) {

        this.setDataLoader(trustedListsCertificateSource.dataLoader);
        this.setCheckSignature(trustedListsCertificateSource.checkSignature);
        this.setLotlCertificate(trustedListsCertificateSource.lotlCertificate);
        this.setLotlUrl(trustedListsCertificateSource.lotlUrl);

    }

    @Override
    protected CertificateSourceType getCertificateSourceType() {

        return CertificateSourceType.TRUSTED_LIST;
    }

    /**
     * This method allows to define (to add) any certificate as trusted. A service information is associated to this certificate. The
     * source of the certificate is set to <code>CertificateSourceType.TRUSTED_LIST</code>
     *
     * @param cert        the certificate you have to trust
     * @param serviceInfo the service information associated to the service
     * @return the corresponding certificate token
     */
    public CertificateToken addCertificate(final X509Certificate cert, final ServiceInfo serviceInfo) {

        final CertificateToken certToken = super.addCertificate(cert, serviceInfo);
        return certToken;
    }

    /**
     * This method method is not applicable for this kind of certificate source. You should use {@link
     * #addCertificate(java.security.cert.X509Certificate, eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo)}
     *
     * @param cert the certificate you have to trust
     * @return the corresponding certificate token
     */
    @Override
    public CertificateToken addCertificate(final X509Certificate cert) {

        throw new DSSException(
              "This method method is not applicable for this kind of certificates source. You should use {@link #addCertificate(java.security.signingCert.X509Certificate, eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo)}");
    }

    /**
     * Adds a service entry (current or history) to the list of certificate tokens.
     *
     * @param cert           the certificate which identifies the trusted service
     * @param trustedService Object defining the trusted service
     * @param tsProvider     Object defining the trusted service provider, must be the parent of the trusted service
     * @param tlWellSigned   Indicates if the signature of trusted list is valid
     */
    private void addCertificate(final X509Certificate cert, final AbstractTrustService trustedService, final TrustServiceProvider tsProvider,
                                final boolean tlWellSigned) {

        try {

            final ServiceInfo serviceInfo = getServiceInfo(trustedService, tsProvider, tlWellSigned);
            super.addCertificate(cert, serviceInfo);
        } catch (NotETSICompliantException ex) {

            LOG.log(Level.SEVERE,
                  "The entry for " + trustedService.getServiceName() + " doesn't respect ESTI specification " + ex.getLocalizedMessage());
        }
    }

    /**
     * This method return the service info object enclosing the certificate.
     *
     * @param trustedService Object defining the trusted service
     * @param tsProvider     Object defining the trusted service provider, must be the parent of the trusted service
     * @param tlWellSigned   Indicates if the signature of trusted list is valid
     * @return
     */
    private ServiceInfo getServiceInfo(final AbstractTrustService trustedService, final TrustServiceProvider tsProvider, final boolean tlWellSigned) {

        final ServiceInfo serviceInfo = trustedService.createServiceInfo();

        serviceInfo.setServiceName(trustedService.getServiceName());
        serviceInfo.setStatus(trustedService.getStatus());
        serviceInfo.setStatusStartDate(trustedService.getStatusStartDate());
        serviceInfo.setStatusEndDate(trustedService.getStatusEndDate());
        serviceInfo.setType(trustedService.getType());

        serviceInfo.setTspElectronicAddress(tsProvider.getElectronicAddress());
        serviceInfo.setTspName(tsProvider.getName());
        serviceInfo.setTspPostalAddress(tsProvider.getPostalAddress());
        serviceInfo.setTspTradeName(tsProvider.getTradeName());

        serviceInfo.setTlWellSigned(tlWellSigned);

        return serviceInfo;
    }

    /**
     * This method returns the diagnostic data concerning the certificates retrieval process from the trusted lists. It can be used for
     * debugging purposes.
     *
     * @return the diagnosticInfo
     */
    public Map<String, String> getDiagnosticInfo() {

        return Collections.unmodifiableMap(diagnosticInfo);
    }

    /**
     * Gets the LOTL certificate as an inputStream stream
     *
     * @return the inputStream stream
     * @throws IOException
     */
    private InputStream getLotlCertificateInputStream() throws DSSException {

        InputStream inputStream = null;
        try {

            if (lotlCertificate.toLowerCase().startsWith(CP)) {

                final String lotlCertificate_ = lotlCertificate.substring(CP.length() - 1);
                inputStream = getClass().getResourceAsStream(lotlCertificate_);
            } else if (lotlCertificate.toLowerCase().startsWith(FILE)) {

                final URL url = new File(lotlCertificate.substring(FILE.length())).toURI().toURL();
                inputStream = url.openStream();
            } else {

                final URL url = new URL(lotlCertificate);
                inputStream = url.openStream();
            }
            return inputStream;
        } catch (Exception e) {

            IOUtils.closeQuietly(inputStream);
            throw new DSSException(e);
        }
    }

    /**
     * Load a trusted list for the specified URL
     *
     * @param url
     * @param signerCert
     * @return
     * @throws IOException
     */
    private TrustStatusList getTrustStatusList(String url, X509Certificate signerCert) {

        InputStream input = null;
        try {

            input = dataLoader.get(url);
            if (input == null) {

                throw new DSSNullReturnedException("The loader returned a null InputStream for: " + url);
            }
            if (url.toLowerCase().endsWith(".zip")) {

                input = getZippedData(input);
            }

            Document doc = DSSXMLUtils.buildDOM(input);

            boolean coreValidity = true;
            if (checkSignature) {

                coreValidity = false;
                if (signerCert != null) {

                    final NodeList signatureNodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
                    if (signatureNodeList.getLength() == 0) {

                        throw new DSSException("Not ETSI compliant signature. The Xml is not signed.");
                    }
                    if (signatureNodeList.getLength() > 1) {

                        throw new DSSException("Not ETSI compliant signature. There is more than one signature.");
                    }
                    final Element signatureEl = (Element) signatureNodeList.item(0);

                    final KeySelector keySelector = KeySelector.singletonKeySelector(signerCert.getPublicKey());
                    final DOMValidateContext valContext = new DOMValidateContext(keySelector, signatureEl);
                    final TSLURIDereferencer tsluriDereferencer = new TSLURIDereferencer(signatureEl);
                    valContext.setURIDereferencer(tsluriDereferencer);
                    final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
                    final XMLSignature signature = factory.unmarshalXMLSignature(valContext);
                    coreValidity = signature.validate(valContext);
                    LOG.info("The TSL signature validity: " + coreValidity);
                }
            }
            final TrustStatusList tsl = TrustServiceListFactory.newInstance(doc);
            tsl.setWellSigned(coreValidity);
            return tsl;
        } catch (DSSException e) {

            throw e;
        } catch (Exception e) {

            throw new DSSException(e);
        } finally {

            DSSUtils.closeQuietly(input);
        }
    }

    /**
     * Solution to manage (known) zipped data by convention a zipped tsl has a url with that suffix.
     *
     * @param inputStream
     * @return
     * @throws IOException
     */
    private InputStream getZippedData(final InputStream inputStream) {

        byte[] inputStreamBytes = null;
        ZipInputStream zipInputStream = null;
        try {

            inputStreamBytes = IOUtils.toByteArray(inputStream);
            IOUtils.closeQuietly(inputStream);
            final InputStream duplicatedInputStream = new ByteArrayInputStream(inputStreamBytes);
            zipInputStream = new ZipInputStream(duplicatedInputStream);
            while (true) {

                final ZipEntry entry = zipInputStream.getNextEntry();
                if (entry == null) {

                    break;
                }
                // by convention, the first file with xml suffix is used
                if (entry.getName().toLowerCase().endsWith(".xml")) {

                    /**
                     * If found, just use the zip stream as inputStream. Only the relevant part of the underlying stream will
                     * be used and automatically closed.
                     */
                    return zipInputStream;
                }
            }
        } catch (Exception e) {

            LOG.log(Level.WARNING, "The data is assumed to be zip format; cannot not be read; continue as xml.", e);
        }
        // if the xml was inspected but not found
        if (zipInputStream != null) {

            // close the zip stream (closes also the underlying one)
            IOUtils.closeQuietly(zipInputStream);
        }
        final InputStream originalInputStream = new ByteArrayInputStream(inputStreamBytes);
        return originalInputStream;
    }

    /**
     * Load the certificates contained in all the TSL referenced by the LOTL
     *
     * @throws IOException
     */
    public void init() {

        diagnosticInfo.clear();

        X509Certificate lotlCert = null;
        if (checkSignature) {

            lotlCert = readLOTLCertificate();
        }
        TrustStatusList lotl;
        try {

            if (LOG.isLoggable(Level.INFO)) {

                LOG.info("Downloading LOTL from url= " + lotlUrl);
            }
            lotl = getTrustStatusList(lotlUrl, lotlCert);
        } catch (DSSException e) {

            LOG.log(Level.SEVERE, "The LOTL cannot be loaded: " + e.getMessage(), e);
            throw e;
        }
        diagnosticInfo.put(lotlUrl, "Loaded " + new Date().toString());
        for (PointerToOtherTSL pointerToTSL : lotl.getOtherTSLPointers()) {

            try {

                final String url = pointerToTSL.getTslLocation();
                final String territory = pointerToTSL.getTerritory();
                final X509Certificate signingCert = pointerToTSL.getDigitalIdentity();

                loadTSL(url, territory, signingCert);
            } catch (DSSException e) {

                // do nothing continue with the next trusted list.
            }
        }
        loadAdditionalLists();
    }

    private X509Certificate readLOTLCertificate() throws DSSException {

        X509Certificate lotlCert;
        if (lotlCertificate == null) {

            final String msg = "The LOTL signing certificate property must contain a reference to a certificate.";
            diagnosticInfo.put(lotlUrl, msg);
            throw new DSSException(msg);
        }
        InputStream inputStream = null;
        try {

            inputStream = getLotlCertificateInputStream();
            lotlCert = DSSUtils.loadCertificate(inputStream);
        } catch (DSSException e) {

            final String msg = "Cannot read LOTL signing certificate.";
            diagnosticInfo.put(lotlUrl, msg);
            throw e;
        } finally {

            DSSUtils.closeQuietly(inputStream);
        }
        return lotlCert;
    }

    /**
     * This method gives  eh possibility to extend this class and to add other trusted lists.
     */
    protected void loadAdditionalLists(final String... urls) {

    }

    /**
     * @param url
     * @param territory
     * @param signingCert
     */
    protected void loadTSL(final String url, final String territory, final X509Certificate signingCert) {

        try {

            diagnosticInfo.put(url, "Loading");
            if (LOG.isLoggable(Level.INFO)) {

                LOG.info("Downloading TrustStatusList for '" + territory + "' from url= " + url);
            }
            final TrustStatusList countryTSL = getTrustStatusList(url, signingCert);
            loadAllCertificatesFromOneTSL(countryTSL);
            diagnosticInfo.put(url, "Loaded " + new Date().toString());
        } catch (final DSSNullReturnedException e) {

            LOG.info("Download skipped.");
            // do nothing: it can happened when a mock data loader is used.
        } catch (final DSSException e) {

            throw e;
        } catch (final RuntimeException e) {

            makeATrace(url, "Other problem: " + e.toString(), e);
        }
    }

    private void makeATrace(final String url, final String message, final Exception e) {

        LOG.log(Level.SEVERE, message, e);
        StringWriter w = new StringWriter();
        e.printStackTrace(new PrintWriter(w));
        diagnosticInfo.put(url, w.toString());
    }

    /**
     * Adds all the service entries (current and history) of all the providers of the trusted list to the list of
     * CertificateSource
     *
     * @param trustStatusList
     */
    private void loadAllCertificatesFromOneTSL(final TrustStatusList trustStatusList) {

        for (final TrustServiceProvider trustServiceProvider : trustStatusList.getTrustServicesProvider()) {

            for (final AbstractTrustService trustService : trustServiceProvider.getTrustServiceList()) {

                // System.out.println(trustService.getServiceName());
                // System.out.println(trustService.getType());
                // System.out.println(trustService.getStatus());
                try {
                    for (final X509Certificate x509Certificate : trustService.getDigitalIdentity()) {

                        addCertificate(x509Certificate, trustService, trustServiceProvider, trustStatusList.isWellSigned());
                    }
                } catch (EncodingException e) {

                    // There is a problem when loading the certificate, we continue with the next one.
                    LOG.warning(e.getLocalizedMessage());
                }
            }
        }
    }

    /**
     * Defines if the TL signature must be checked.
     *
     * @param checkSignature the checkSignature to set
     */
    public void setCheckSignature(boolean checkSignature) {

        this.checkSignature = checkSignature;
    }

    /**
     * @param lotlCertificate the lotlCertificate to set
     */
    public void setLotlCertificate(String lotlCertificate) {

        this.lotlCertificate = lotlCertificate;
    }

    /**
     * Define the URL of the LOTL
     *
     * @param lotlUrl the lotlUrl to set
     */
    public void setLotlUrl(String lotlUrl) {

        this.lotlUrl = lotlUrl;
    }

    /**
     * @param dataLoader the dataLoader to set
     */
    public void setDataLoader(HTTPDataLoader dataLoader) {

        this.dataLoader = dataLoader;
    }
}
