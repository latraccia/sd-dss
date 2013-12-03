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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.validation.ades.SignatureCertificateSource;

/**
 * 
 * Retrieve Certificates contained in a XAdES structure
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class XAdESCertificateSource extends SignatureCertificateSource {

	private final Element signatureElement;

	private final boolean onlyExtended;

	/**
	 * 
	 * The default constructor for XAdESCertificateSource.
	 * 
	 * @param signatureElement
	 */
	public XAdESCertificateSource(Element signatureElement, boolean onlyExtended) {

		this.signatureElement = signatureElement;
		this.onlyExtended = onlyExtended;
	}

	/**
	 * 
	 * @param signatureElement
	 * @param node
	 * @return
	 * @throws CertificateException
	 */
	private List<X509Certificate> getCerts(Element signatureElement, String node) throws CertificateException {

		List<X509Certificate> list = new ArrayList<X509Certificate>();
		try {

			NodeList nodeList = DSSXMLUtils.getNodeList(signatureElement, node);
			CertificateFactory factory = CertificateFactory.getInstance("X509");
			for (int i = 0; i < nodeList.getLength(); i++) {

				Element certEl = (Element) nodeList.item(i);
				byte[] derEncoded = DSSUtils.base64Decode(certEl.getTextContent());
				X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(derEncoded));
				if (!list.contains(cert)) {

					list.add(cert);
				}
			}
		} catch (CertificateException e) {

			throw new RuntimeException(e);
		}
		return list;
	}

	/*
	 * Returns the list of certificates encapsulated in the signature
	 * 
	 * @see eu.europa.ec.markt.dss.validation.certificate.OfflineCertificateSource#getCertificates()
	 */
	@Override
	public List<X509Certificate> getCertificates() {

		List<X509Certificate> list = new ArrayList<X509Certificate>();
		try {

			list.addAll(getCerts(signatureElement, XAdESSignature.XPATH_ENCAPSULATED_X509_CERTIFICATE));
			if (!onlyExtended) {

				list.addAll(getCerts(signatureElement, XAdESSignature.XPATH_X509_CERTIFICATE));
			}
		} catch (CertificateException e) {

			throw new RuntimeException(e);
		}
		return list;
	}

	/**
	 * Returns the list of certificates included in "ds:KeyInfo/ds:X509Data/ds:X509Certificate" node
	 * 
	 * @return list of X509Certificate(s)
	 */
	public List<X509Certificate> getKeyInfoCertificates() {

		try {

			return getCerts(signatureElement, XAdESSignature.XPATH_X509_CERTIFICATE);
		} catch (CertificateException e) {

			throw new RuntimeException(e);
		}
	}
}
