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

package eu.europa.ec.markt.dss.validation.xades;

import java.io.ByteArrayInputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.ades.SignatureCRLSource;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;

/**
 * 
 * Retrieves CRL values from an XAdES (-XL) signature.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class XAdESCRLSource extends SignatureCRLSource {

	/**
	 * The element of the XML tree that contains the signature.
	 */
	private Element signatureElement;

	/**
	 * List of contained X509CRL.
	 */
	List<X509CRL> list;

	/**
	 * 
	 * The default constructor for XAdESCRLSource.
	 * 
	 * @param signatureElement
	 */
	public XAdESCRLSource(Element signatureElement) {

		this.signatureElement = signatureElement;
	}

	@Override
	public List<X509CRL> getContainedCRLs() {

		List<X509CRL> list = new ArrayList<X509CRL>();
		try {

			NodeList nodeList = (NodeList) DSSXMLUtils.getNodeList(signatureElement, XAdESSignature.XPATH_ENCAPSULATED_CRL_VALUE);
			for (int i = 0; i < nodeList.getLength(); i++) {

				Element certEl = (Element) nodeList.item(i);
				CertificateFactory factory = CertificateFactory.getInstance("X509");
				byte[] derEncoded;
				derEncoded = DSSUtils.base64Decode(certEl.getTextContent());
				X509CRL cert = (X509CRL) factory.generateCRL(new ByteArrayInputStream(derEncoded));
				list.add(cert);
			}
		} catch (CertificateException e) {

			throw new DSSException(e);
		} catch (CRLException e) {

			throw new DSSException(e);
		}
		return list.size() > 0 ? list : null;
	}
}
