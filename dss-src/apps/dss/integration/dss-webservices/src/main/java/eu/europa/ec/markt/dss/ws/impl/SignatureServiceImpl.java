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

package eu.europa.ec.markt.dss.ws.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.jws.WebService;

import org.apache.commons.io.IOUtils;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.ws.SignatureService;
import eu.europa.ec.markt.dss.ws.SignedPropertiesContainer;
import eu.europa.ec.markt.dss.ws.WSDocument;

/**
 * Implementation of the Interface for the Contract of the Signature Web Service.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

@WebService(endpointInterface = "eu.europa.ec.markt.dss.ws.SignatureService", serviceName = "SignatureService")
public class SignatureServiceImpl implements SignatureService {

	private DocumentSignatureService cadesService;

	private DocumentSignatureService xadesService;

	private DocumentSignatureService padesService;

	/**
	 * @param cadesService the cadesService to set
	 */
	public void setCadesService(DocumentSignatureService cadesService) {

		this.cadesService = cadesService;
	}

	/**
	 * @param padesService the padesService to set
	 */
	public void setPadesService(DocumentSignatureService padesService) {

		this.padesService = padesService;
	}

	/**
	 * @param xadesService the xadesService to set
	 */
	public void setXadesService(DocumentSignatureService xadesService) {

		this.xadesService = xadesService;
	}

	private DocumentSignatureService getServiceForSignatureFormat(SignatureFormat signatureInfoLevel) {

		switch (signatureInfoLevel) {
		case CAdES_A:
		case CAdES_BES:
		case CAdES_C:
		case CAdES_EPES:
		case CAdES_T:
		case CAdES_X:
		case CAdES_XL:
			return cadesService;
		case PAdES_BES:
		case PAdES_EPES:
		case PAdES_LTV:
			return padesService;
		case XAdES_A:
		case XAdES_BES:
		case XAdES_C:
		case XAdES_EPES:
		case XAdES_T:
		case XAdES_X:
		case XAdES_XL:
			return xadesService;
		default:
			throw new IllegalArgumentException("Unrecognized format " + signatureInfoLevel);
		}

	}

	private SignatureParameters createParameters(SignatureFormat signatureInfoLevel) throws IOException {

		return createParameters(signatureInfoLevel, null);
	}

	private SignatureParameters createParameters(SignatureFormat signatureInfoLevel, SignedPropertiesContainer container) throws IOException {

		SignatureParameters params = new SignatureParameters();
		params.setSignatureFormat(signatureInfoLevel);
		if (container != null) {
			params.setClaimedSignerRole(container.getClaimedSignerRole());
			params.setSignaturePackaging(SignaturePackaging.valueOf(container.getSignaturePackaging()));
			params.setSigningDate(container.getSigningDate());

			try {
				CertificateFactory factory = CertificateFactory.getInstance("X509");
				params.setSigningCertificate((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(container.getSigningCertificate())));
				List<X509Certificate> chain = new ArrayList<X509Certificate>();
				for (byte[] cert : container.getCertificateChain()) {
					chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cert)));
				}
				params.setCertificateChain(chain);
			} catch (CertificateException ex) {
				throw new IOException("Cannot read certficate");
			}
		}

		return params;
	}

	@Override
	public byte[] digestDocument(WSDocument document, SignedPropertiesContainer signedPropertiesContainer, SignatureFormat signatureInfo)
			throws IOException {

		SignatureParameters params = createParameters(signatureInfo, signedPropertiesContainer);
		DocumentSignatureService service = getServiceForSignatureFormat(signatureInfo);
		try {
			return IOUtils.toByteArray(service.toBeSigned(document, params));
		} catch (DSSException e) {

			throw new IOException(e);
		}
	}

	@Override
	public WSDocument signDocument(WSDocument document, byte[] signedDigest, SignedPropertiesContainer signedPropertiesContainer,
			SignatureFormat signatureInfoLevel) throws IOException {

		SignatureParameters params = createParameters(signatureInfoLevel, signedPropertiesContainer);
		DocumentSignatureService service = getServiceForSignatureFormat(signatureInfoLevel);
		try {
			return new WSDocument(service.signDocument(document, params, signedDigest));
		} catch (DSSException e) {

			throw new IOException(e);
		}
	}

	@Override
	public WSDocument extendSignature(WSDocument signedDocument, WSDocument originalDocument, SignatureFormat signatureInfoLevel) throws IOException {

		SignatureParameters params = createParameters(signatureInfoLevel);
		DocumentSignatureService service = getServiceForSignatureFormat(signatureInfoLevel);
		return new WSDocument(service.extendDocument(signedDocument, originalDocument, params));
	}

}