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

package eu.europa.ec.markt.dss.validation102853;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.StoreException;

import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * CertificateSource that retrieves items from a CAdES Signature
 *
 * @version $Revision: 1821 $ - $Date: 2013-03-28 15:56:00 +0100 (Thu, 28 Mar 2013) $
 */

public class CAdESCertificateSource extends SignatureCertificateSource {

    private static final Logger LOG = Logger.getLogger(CAdESCertificateSource.class.getName());

    final private CMSSignedData cmsSignedData;
    final SignerId signerId;

    private List<CertificateToken> keyInfoCerts;
    private List<CertificateToken> encapsulatedCerts;

    /**
     * The default constructor for CAdESCertificateSource. All certificates are extracted during instantiation.
     *
     * @param cms
     * @throws CMSException
     */
    public CAdESCertificateSource(final CMSSignedData cms, final CertificatePool certPool) {

        this(cms, ((SignerInformation) cms.getSignerInfos().getSigners().iterator().next()).getSID(), certPool);
    }

    /**
     * The constructor with additional signer id parameter. All certificates are extracted during instantiation.
     *
     * @param cmsSignedData
     * @param signerId
     */
    public CAdESCertificateSource(final CMSSignedData cmsSignedData, final SignerId signerId, final CertificatePool certPool) {

        super(certPool);
        if (cmsSignedData == null) {

            throw new DSSException("cmsSignedData is null, it must be provided!");
        }
        this.cmsSignedData = cmsSignedData;
        this.signerId = signerId;
        extract();
        if (LOG.isLoggable(Level.INFO)) {

            LOG.info("+ CAdESCertificateSource for issuer: " + signerId.getIssuerAsString());
        }
    }

    @Override
    protected void extract() throws DSSException {

        if (certificateTokens == null) {

            certificateTokens = new ArrayList<CertificateToken>();
            keyInfoCerts = extractKeyInfoCertificates();
            encapsulatedCerts = extractEncapsulatedCertificates();
        }
    }

    /**
     * Returns the list of certificates included in (XAdES equivalent)
     * ".../xades:UnsignedSignatureProperties/xades:CertificateValues/xades:EncapsulatedX509Certificate" node
     *
     * @return list of X509Certificate(s)
     */
    public List<CertificateToken> getEncapsulatedCertificates() throws DSSException {

        return encapsulatedCerts;
    }

    /**
     * @throws DSSException
     */
    private ArrayList<CertificateToken> extractEncapsulatedCertificates() throws DSSException {

        final ArrayList<CertificateToken> encapsulatedCerts = new ArrayList<CertificateToken>();
        try {

            // Gets certificates from CAdES-XL certificate-values inside SignerInfo attribute if present
            final SignerInformation si = cmsSignedData.getSignerInfos().get(signerId);
            if (si != null && si.getUnsignedAttributes() != null) {

                final Attribute attr = si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certValues);
                if (attr != null) {

                    final DERSequence seq = (DERSequence) attr.getAttrValues().getObjectAt(0);
                    for (int ii = 0; ii < seq.size(); ii++) {

                        final X509CertificateStructure cs = X509CertificateStructure.getInstance(seq.getObjectAt(ii));
                        final X509Certificate cert = new X509CertificateObject(cs);
                        final CertificateToken certToken = addCertificate(cert);
                        encapsulatedCerts.add(certToken);
                    }
                }
            }
        } catch (CertificateParsingException e) {

            throw new DSSException(e);
        }
        return encapsulatedCerts;
    }

    /**
     * Returns the list of certificates included in (XAdES equivalent) "ds:KeyInfo/ds:X509Data/ds:X509Certificate" node
     *
     * @return list of X509Certificate(s)
     */
    public List<CertificateToken> getKeyInfoCertificates() throws DSSException {

        return keyInfoCerts;
    }

    /**
     * @throws StoreException
     * @throws DSSException
     */
    @SuppressWarnings("unchecked")
    private ArrayList<CertificateToken> extractKeyInfoCertificates() throws StoreException, DSSException {

        final ArrayList<CertificateToken> keyInfoCerts = new ArrayList<CertificateToken>();
        try {

            for (final X509CertificateHolder certHolder : (Collection<X509CertificateHolder>) cmsSignedData.getCertificates().getMatches(null)) {

                final X509Certificate cert = new X509CertificateObject(certHolder.toASN1Structure());
                final CertificateToken certToken = addCertificate(cert);
                // System.out.println(" --- > " + certToken.getIssuerX500Principal());
                keyInfoCerts.add(certToken);
            }
        } catch (CertificateParsingException e) {

            throw new DSSException(e);
        }
        return keyInfoCerts;
    }
}
