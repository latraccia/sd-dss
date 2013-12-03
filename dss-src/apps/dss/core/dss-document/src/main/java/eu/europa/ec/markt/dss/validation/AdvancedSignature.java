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

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.ocsp.BasicOCSPResp;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.crl.CRLSource;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPSource;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

/**
 * Provides an abstraction for an Advanced Electronic Signature. This ease the validation process. Every signature
 * format : XAdES, CAdES and PAdES are treated the same.
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */
public interface AdvancedSignature {

	/**
	 * Specifies the format of the signature
	 */
	SignatureForm getSignatureFormat();

	/**
	 * Retrieves the signature algorithm (or cipher) used for generating the signature
	 * 
	 * @return
	 */
	String getSignatureAlgorithm();

	/**
	 * Gets a certificate source for the ALL certificates embedded in the signature
	 * 
	 * @return
	 * @throws Exception
	 */
	CertificateSource getCertificateSource();

	/**
	 * Return only the certificates that are in the -XL/-LTV structure.
	 * 
	 * @return
	 */
	CertificateSource getExtendedCertificateSource();

	/**
	 * Get certificates embedded in the signature
	 * 
	 * @reutrn a list of certificate contained in the signature
	 */
	List<X509Certificate> getCertificates();

	/**
	 * Gets a CRL source for the CRLs embedded in the signature
	 * 
	 * @return
	 * @throws Exception
	 */
	CRLSource getCRLSource();

	/**
	 * Gets an OCSP source for the OCSP responses embedded in the signature
	 * 
	 * @return
	 * @throws Exception
	 */
	OCSPSource getOCSPSource();

	/**
	 * Get the signing certificate
	 * 
	 * @return
	 */
	X509Certificate getSigningCertificate();

	/**
	 * Returns the signing time information
	 * 
	 * @return
	 */
	Date getSigningTime();

	/**
	 * Returns the Signature Policy OID from the signature
	 * 
	 * @return
	 */
	PolicyValue getPolicyId();

	/**
	 * Return information about the place where the signature was generated
	 * 
	 * @return
	 */
	String getLocation();

	/**
	 * Returns the content type of the signed data
	 * 
	 * @return
	 */
	String getContentType();

	/**
	 * Returns the claimed role of the signer.
	 * 
	 * @return
	 */
	String[] getClaimedSignerRoles();

	/**
	 * Returns the signature timestamps
	 * 
	 * @return
	 */
	List<TimestampToken> getSignatureTimestamps();

	/**
	 * Returns the data that is timestamped in the SignatureTimeStamp
	 * 
	 * @return
	 */
	byte[] getSignatureTimestampData();

	/**
	 * Archive timestamp seals the data of the signature in a specific order. We need to retrieve the data for each
	 * timestamp.
	 * 
	 * @return
	 */
	public byte[] getArchiveTimestampData(int index, DSSDocument originalData);

	/**
	 * Returns the timestamp over the certificate/revocation references (and optionally other fields), used in -X
	 * profiles
	 */
	List<TimestampToken> getTimestampsX1();

	/**
	 * 
	 * @return
	 */
	List<TimestampToken> getTimestampsX2();

	/**
	 * Returns the archive TimeStamps
	 * 
	 * @return
	 */
	List<TimestampToken> getArchiveTimestamps();

	/**
	 * Verify the signature integrity; checks if the signed content has not been tampered with
	 * 
	 * @param detachedDocument the original document concerned by the signature if not part of the actual object
	 * @return true if the signature is valid
	 */
	boolean checkIntegrity(DSSDocument detachedDocument) throws DSSException;

	/**
	 * Returns a list of counter signatures applied to this signature
	 * 
	 * @return a list of AdvancedSignatures representing the counter signatures
	 */
	List<AdvancedSignature> getCounterSignatures();

	/**
	 * Retrieve list of certificate ref
	 * 
	 * @return
	 */
	List<CertificateRef> getCertificateRefs();

	/**
	 * 
	 * @return The list of CRLRefs contained in the Signature
	 */
	List<CRLRef> getCRLRefs();

	/**
	 * 
	 * @return The list of OCSPRef contained in the Signature
	 */
	List<OCSPRef> getOCSPRefs();

	/**
	 * 
	 * @return The list of X509CRL contained in the Signature
	 */
	List<X509CRL> getCRLs();

	/**
	 * 
	 * @return The list of BasicOCSResp contained in the Signature
	 */
	List<BasicOCSPResp> getOCSPs();

	/**
	 * 
	 * @return The byte array digested to create a TimeStamp X1
	 */
	byte[] getTimestampX1Data();

	/**
	 * 
	 * @return The byte array digested to create a TimeStamp X2
	 */
	byte[] getTimestampX2Data();

	/**
	 * 
	 * @return The signature unique Id
	 */
	String getId();

}
