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

package eu.europa.ec.markt.dss.signature.cades;

import java.io.IOException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.ocsp.BasicOCSPResp;

import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;

/**
 * This class holds the CAdES-X signature profiles; it supports the inclusion of a combination of the unsigned
 * attributes id-aa-ets-escTimeStamp, id-aa-ets-certCRLTimestamp, id-aa-ets-certValues, id-aa-ets-revocationValues as
 * defined in ETSI TS 101 733 V1.8.1, clause 6.3.
 * 
 * 
 * @version $Revision: 1817 $ - $Date: 2013-03-28 15:54:49 +0100 (jeu., 28 mars 2013) $
 */

public class CAdESProfileXL extends CAdESProfileX {

	private static final Logger LOG = Logger.getLogger(CAdESProfileXL.class.getName());

	private Hashtable<ASN1ObjectIdentifier, ASN1Encodable> extendUnsignedAttributes(Hashtable<ASN1ObjectIdentifier, ASN1Encodable> unsignedAttrs,
			X509Certificate signingCertificate, Date signingDate, CertificateSource optionalCertificateSource) throws IOException {

		ValidationContext validationContext = certificateVerifier.validateCertificate(signingCertificate, signingDate, optionalCertificateSource, null,
				null);

		try {

			List<X509CertificateStructure> certificateValues = new ArrayList<X509CertificateStructure>();
			ArrayList<CertificateList> crlValues = new ArrayList<CertificateList>();
			ArrayList<BasicOCSPResponse> ocspValues = new ArrayList<BasicOCSPResponse>();

			/*
			 * The ETSI TS 101 733 stipulates (§6.2.1): "It references the full set of CA certificates that have been used
			 * to validate an ES with Complete validation data up to (but not including) the signer's certificate. [...]
			 * NOTE 1: The signer's certificate is referenced in the signing certificate attribute (see clause 5.7.3)."
			 * (§6.2.1)
			 * 
			 * "The second and subsequent CrlOcspRef fields shall be in the same order as the OtherCertID to which they
			 * relate." (§6.2.2)
			 * 
			 * Also, no mention of the way to order those second and subsequent fields, so we add the certificates as
			 * provided by the context.
			 */

			/* The SignedCertificate is in validationContext.getCertificate() */

			for (CertificateAndContext c : validationContext.getNeededCertificates()) {

				/*
				 * Add every certificate except the signing certificate
				 */
				if (!c.getCertificate().equals(signingCertificate)) {

					certificateValues.add(new X509CertificateStructure((ASN1Sequence) ASN1Object.fromByteArray(c.getCertificate().getEncoded())));
				}
			}

			/*
			 * Record each CRL and OCSP with a reference to the corresponding certificate
			 */
			for (CRL relatedcrl : validationContext.getNeededCRL()) {
				crlValues.add(new CertificateList((ASN1Sequence) ASN1Object.fromByteArray(((X509CRL) relatedcrl).getEncoded())));
			}

			for (BasicOCSPResp relatedocspresp : validationContext.getNeededOCSPResp()) {
				ocspValues.add((new BasicOCSPResponse((ASN1Sequence) ASN1Object.fromByteArray(relatedocspresp.getEncoded()))));
			}

			CertificateList[] crlValuesArray = new CertificateList[crlValues.size()];
			BasicOCSPResponse[] ocspValuesArray = new BasicOCSPResponse[ocspValues.size()];
			RevocationValues revocationValues = new RevocationValues(crlValues.toArray(crlValuesArray), ocspValues.toArray(ocspValuesArray), null);
			unsignedAttrs.put(PKCSObjectIdentifiers.id_aa_ets_revocationValues, new Attribute(PKCSObjectIdentifiers.id_aa_ets_revocationValues,
					new DERSet(revocationValues)));

			X509CertificateStructure[] certValuesArray = new X509CertificateStructure[certificateValues.size()];
			unsignedAttrs.put(PKCSObjectIdentifiers.id_aa_ets_certValues, new Attribute(PKCSObjectIdentifiers.id_aa_ets_certValues, new DERSet(
					new DERSequence(certificateValues.toArray(certValuesArray)))));

		} catch (CertificateEncodingException e) {
			throw new RuntimeException(e);
		} catch (CRLException e) {
			throw new RuntimeException(e);
		}

		return unsignedAttrs;

	}

	@SuppressWarnings("unchecked")
	@Override
	protected SignerInformation extendCMSSignature(CMSSignedData signedData, SignerInformation si, SignatureParameters parameters) throws IOException {

		si = super.extendCMSSignature(signedData, si, parameters);
		LOG.info(">>>CAdESProfileXL::extendCMSSignature");
		Hashtable<ASN1ObjectIdentifier, ASN1Encodable> unsignedAttrs = si.getUnsignedAttributes().toHashtable();

		/* Extends unsigned attributes */
		CAdESSignature signature = new CAdESSignature(signedData, si.getSID());
		Date signingTime = signature.getSigningTime();
		if (signingTime == null) {
			signingTime = parameters.getSigningDate();
		}
		if (signingTime == null) {
			signingTime = new Date();
		}
		unsignedAttrs = extendUnsignedAttributes(unsignedAttrs, signature.getSigningCertificate(), signingTime, signature.getCertificateSource());

		SignerInformation newsi = SignerInformation.replaceUnsignedAttributes(si, new AttributeTable(unsignedAttrs));
		return newsi;
	}

}
