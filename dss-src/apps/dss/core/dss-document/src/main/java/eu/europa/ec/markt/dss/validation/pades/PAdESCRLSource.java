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

package eu.europa.ec.markt.dss.validation.pades;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.validation.ades.SignatureCRLSource;

/**
 * CRLSource that will retrieve the CRL from a PAdES Signature
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class PAdESCRLSource extends SignatureCRLSource {

	private PdfDict catalog;

	/**
	 * The default constructor for PAdESCRLSource.
	 * 
	 * @param catalog
	 */
	public PAdESCRLSource(PdfDict catalog) {

		this.catalog = catalog;
	}

	@Override
	public List<X509CRL> getContainedCRLs() {

		try {

			List<X509CRL> list = new ArrayList<X509CRL>();
			PdfDict dss = catalog.getAsDict("DSS");
			if (dss != null) {

				PdfArray crlArray = dss.getAsArray("CRLs");
				if (crlArray != null) {

					CertificateFactory factory = CertificateFactory.getInstance("X509");
					for (int i = 0; i < crlArray.size(); i++) {

						byte[] stream = crlArray.getBytes(i);
						X509CRL cert = (X509CRL) factory.generateCRL(new ByteArrayInputStream(stream));
						if (!list.contains(cert)) {

							list.add(cert);
						}
					}
				}
			}
			return list.size() > 0 ? list : null;
		} catch (IOException ex) {

			throw new DSSException(ex);
		} catch (CertificateException e) {

			throw new DSSException(e);
		} catch (CRLException e) {

			throw new DSSException(e);
		}
	}
}
