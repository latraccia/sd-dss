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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.validation.ades.SignatureOCSPSource;

/**
 * OCSPSource that retrieves the OCSPResp from a PAdES Signature
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class PAdESOCSPSource extends SignatureOCSPSource {

	// private Logger LOG = Logger.getLogger(PAdESOCSPSource.class.getName());

	private PdfDict catalog;

	/**
	 * The default constructor for PAdESOCSPSource.
	 * 
	 * @param catalog
	 */
	public PAdESOCSPSource(PdfDict catalog) {

		this.catalog = catalog;
	}

	@Override
	public List<BasicOCSPResp> getContainedOCSPResponses() {

		try {

			List<BasicOCSPResp> list = new ArrayList<BasicOCSPResp>();
			PdfDict dss = catalog.getAsDict("DSS");
			if (dss != null) {

				PdfArray ocspArray = dss.getAsArray("OCSPs");
				if (ocspArray != null) {

					for (int i = 0; i < ocspArray.size(); i++) {

						byte[] stream = ocspArray.getBytes(i);
						list.add((BasicOCSPResp) new OCSPResp(stream).getResponseObject());
					}
				}
			}
			return list;
		} catch (OCSPException ex) {

			throw new DSSException(ex);
		} catch (IOException ex) {

			throw new DSSException(ex);
		}
	}
}
