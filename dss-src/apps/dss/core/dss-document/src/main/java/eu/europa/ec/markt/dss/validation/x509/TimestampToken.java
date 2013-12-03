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

package eu.europa.ec.markt.dss.validation.x509;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.ec.markt.dss.validation.cades.CAdESCertificateSource;

/**
 * SignedToken containing a TimeStamp.
 * 
 * 
 * @version $Revision: 1927 $ - $Date: 2013-05-08 09:54:30 +0200 (mer., 08 mai 2013) $
 */

public class TimestampToken implements SignedToken {

	/**
	 * Source of the timestamp
	 * 
	 * <p>
	 * DISCLAIMER: Project owner DG-MARKT.
	 * 
	 * @version $Revision: 1927 $ - $Date: 2013-05-08 09:54:30 +0200 (mer., 08 mai 2013) $
	 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
	 */
	public static enum TimestampType {
		CONTENT_TIMESTAMP, // CAdES: id-aa-ets-contentTimestamp, XAdES: AllDataObjectsTimeStamp, PAdES standard
									// timestamp
		INDIVIDUAL_CONTENT_TIMESTAMP, // XAdES: IndividualDataObjectsTimeStamp
		SIGNATURE_TIMESTAMP, // CAdES: id-aa-signatureTimeStampToken, XAdES: SignatureTimeStamp
		VALIDATION_DATA_REFSONLY_TIMESTAMP, // CAdES: id-aa-ets-certCRLTimestamp, XAdES: RefsOnlyTimeStamp
		VALIDATION_DATA_TIMESTAMP, // CAdES: id-aa-ets-escTimeStamp, XAdES: SigAndRefsTimeStamp
		ARCHIVE_TIMESTAMP
		// CAdES: id-aa-ets-archiveTimestamp, XAdES: ArchiveTimeStamp, PAdES-LTV "document timestamp"
	}

	private final TimeStampToken timeStamp;

	private TimestampType timeStampType;

	/**
	 * 
	 * The default constructor for TimestampToken.
	 * 
	 * @param timeStamp
	 */
	public TimestampToken(TimeStampToken timeStamp) {
		this.timeStamp = timeStamp;
	}

	/**
	 * Constructor with an indication of the time-stamp type The default constructor for TimestampToken.
	 */
	public TimestampToken(TimeStampToken timeStamp, TimestampType type) {
		this.timeStamp = timeStamp;
		this.timeStampType = type;
	}

	@Override
	public X500Principal getSignerSubjectName() {
		Collection<X509Certificate> certs = getWrappedCertificateSource().getCertificates();
		for (X509Certificate cert : certs) {
			if (timeStamp.getSID().match(cert)) {
				return cert.getSubjectX500Principal();
			}
		}
		return null;
	}

	@SuppressWarnings("deprecation")
	@Override
	public boolean isSignedBy(X509Certificate potentialIssuer) {
		try {
			timeStamp.validate(potentialIssuer, "BC");
			return true;
		} catch (CertificateExpiredException e) {
			return false;
		} catch (CertificateNotYetValidException e) {
			return false;
		} catch (TSPValidationException e) {
			return false;
		} catch (NoSuchProviderException e) {
			/*
			 * This should never happens. The provider BouncyCastle is supposed to be installed. No special treatment for this
			 * exception
			 */
			throw new RuntimeException(e);
		} catch (TSPException e) {
			return false;
		}
	}

	@Override
	public CAdESCertificateSource getWrappedCertificateSource() {
		return new CAdESCertificateSource(timeStamp.toCMSSignedData());
	}

	/**
	 * @return the timeStampType
	 */
	public TimestampType getTimeStampType() {
		return timeStampType;
	}

	/**
	 * @return the timeStamp token
	 */
	public TimeStampToken getTimeStamp() {
		return timeStamp;
	}

	/**
	 * Check if the TimeStampToken matches the data
	 * 
	 * @param data
	 * @return true if the data are verified by the TimeStampToken
	 * @throws NoSuchAlgorithmException
	 */
	public boolean matchData(byte[] data) throws NoSuchAlgorithmException {
		String hashAlgorithm = timeStamp.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();
		MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
		byte[] computedDigest = digest.digest(data);
		return Arrays.equals(computedDigest, timeStamp.getTimeStampInfo().getMessageImprintDigest());
	}

	/**
	 * Retrieve the timestamp generation date
	 * 
	 * @return
	 */
	public Date getGenTimeDate() {
		return timeStamp.getTimeStampInfo().getGenTime();
	}

	@Override
	public String toString() {

		return toString("");
	}

	@Override
	public String toString(String indentStr) {

		StringBuffer res = new StringBuffer();
		res.append(indentStr).append("TimestampToken[signedBy=").append(getSignerSubjectName()).append("]");
		return res.toString();
	}

}