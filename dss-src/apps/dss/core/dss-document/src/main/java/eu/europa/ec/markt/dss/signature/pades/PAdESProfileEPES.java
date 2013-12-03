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

package eu.europa.ec.markt.dss.signature.pades;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.SignatureParameters.Policy;
import eu.europa.ec.markt.dss.signature.cades.CAdESProfileEPES;

/**
 * EPES profile for PAdES signature
 * 
 * 
 * @version $Revision: 1563 $ - $Date: 2012-12-17 14:33:50 +0100 (lun., 17 déc. 2012) $
 */

public class PAdESProfileEPES {

    private static final Logger LOG = Logger.getLogger(PAdESProfileEPES.class.getName());

    CMSSignedDataGenerator createCMSSignedDataGenerator(ContentSigner contentSigner, DigestCalculatorProvider digestCalculatorProvider, final SignatureParameters parameters, final byte[] messageDigest)
            throws IOException {
        try {

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            X509Certificate signerCertificate = parameters.getSigningCertificate();

            X509CertificateHolder certHolder = new X509CertificateHolder(signerCertificate.getEncoded());

            SignerInfoGeneratorBuilder sigenb = new SignerInfoGeneratorBuilder(digestCalculatorProvider);

            final CAdESProfileEPES profile = new CAdESProfileEPES(true);

            sigenb = sigenb.setSignedAttributeGenerator(new CMSAttributeTableGenerator() {

                @SuppressWarnings("unchecked")
                @Override
                public AttributeTable getAttributes(@SuppressWarnings("rawtypes") Map params) throws CMSAttributeTableGenerationException {

                    @SuppressWarnings("rawtypes")
                    Hashtable clone = (Hashtable) profile.getSignedAttributes(parameters).clone();

                    if (!clone.containsKey(CMSAttributes.contentType)) {

                        DERObjectIdentifier contentType = (DERObjectIdentifier) params.get(CMSAttributeTableGenerator.CONTENT_TYPE);

                        // contentType will be null if we're trying to generate a counter signature.
                        if (contentType != null) {
                            Attribute attr = new Attribute(CMSAttributes.contentType, new DERSet(contentType));
                            clone.put(attr.getAttrType(), attr);
                        }
                    }

                    if (!clone.containsKey(CMSAttributes.messageDigest)) {
                        LOG.log(Level.FINE, "Digest proposé : {0} ", new Object[] { org.apache.commons.codec.binary.Hex.encodeHexString(messageDigest) });
                        // byte[] messageDigest = (byte[]) params.get(CMSAttributeTableGenerator.DIGEST);
                        Attribute attr = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(messageDigest)));
                        clone.put(attr.getAttrType(), attr);
                    }

                    Policy policy = parameters.getSignaturePolicy();
                    if (policy.getCommitmentTypeIndications() != null && !policy.getCommitmentTypeIndications().isEmpty()) {

                        ASN1EncodableVector vector = new ASN1EncodableVector();
                        for (String id : policy.getCommitmentTypeIndications()) {
                            vector.add(new DERObjectIdentifier(id));
                        }
                        DERSet set = new DERSet(new DERSequence(vector));
                        Attribute attr = new Attribute(new DERObjectIdentifier("1.2.840.113549.1.9.16.2.16"), set);
                        clone.put(attr.getAttrType(), attr);
                    }

                    return new AttributeTable(clone);
                }
            });

            // sigenb.setUnsignedAttributeGenerator(new SimpleAttributeTableGenerator(new AttributeTable(
            // new Hashtable<ASN1ObjectIdentifier, ASN1Encodable>())));

            /*
             * We don't include a unsigned attribute table if not needed : a unsignedAttrs of signerInfo includes no
             * Attribute, UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute(defined in RFC3852).
             */
            SignerInfoGenerator sigen = sigenb.build(contentSigner, certHolder);

            generator.addSignerInfoGenerator(sigen);

            Collection<X509Certificate> certs = new ArrayList<X509Certificate>();
            if (parameters.getCertificateChain() == null || !parameters.getCertificateChain().contains(parameters.getSigningCertificate())) {
                certs.add(parameters.getSigningCertificate());
            }
            certs.addAll(parameters.getCertificateChain());
            JcaCertStore certStore = new JcaCertStore(certs);
            generator.addCertificates(certStore);

            return generator;

        } catch (CertificateException e) {
            throw new IOException(e);
        } catch (OperatorCreationException e) {
            throw new IOException(e);
        } catch (CMSException e) {
            throw new IOException(e);
        }

    }
}
