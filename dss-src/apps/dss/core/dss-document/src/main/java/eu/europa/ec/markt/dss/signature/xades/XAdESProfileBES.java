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

package eu.europa.ec.markt.dss.signature.xades;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.apache.xml.security.Init;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.SignatureProfile;

/**
 * Contains BES aspects of XAdES
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class XAdESProfileBES extends SignatureProfile {

	/**
	 * The default constructor for XAdESProfileBES.
	 */
	public XAdESProfileBES() {

		Init.init();
	}

	/**
	 * Returns the <ds:SignedInfo> XML segment under the form of InputStream
	 * 
	 * @param document The original document to sign.
	 * @param params The set of parameters relating to the structure and process of the creation or extension of the
	 *           electronic signature.
	 * @return The returned stream does not need to be closed
	 */
	@Override
	public InputStream getSignedInfoStream(DSSDocument document, SignatureParameters params) {

		try {

			SignatureBuilder builder = SignatureBuilder.getSignatureBuilder(params, document);
			params.getContext().setBuilder(builder);
			return new ByteArrayInputStream(builder.build());
		} catch (Exception e) {

			throw new DSSException(e);
		}
	}

	/*
	 * Adds the signature value to the signature
	 * 
	 * @see eu.europa.ec.markt.dss.signature.SignatureProfile#signDocument(eu.europa.ec.markt.dss.signature.Document,
	 * eu.europa.ec.markt.dss.signature.SignatureParameters, byte[])
	 */
	@Override
	public DSSDocument signDocument(DSSDocument document, SignatureParameters parameters, byte[] signatureValue) throws DSSException {

		SignatureBuilder builder;
		if (parameters.getContext().getBuilder() != null) {

			builder = parameters.getContext().getBuilder();
		} else {

			builder = SignatureBuilder.getSignatureBuilder(parameters, document);
		}
		DSSDocument document_ = builder.signDocument(signatureValue);
		parameters.getContext().setBuilder(builder);
		return document_;
	}
}
