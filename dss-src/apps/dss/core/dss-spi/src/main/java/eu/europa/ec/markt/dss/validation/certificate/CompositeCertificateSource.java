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

package eu.europa.ec.markt.dss.validation.certificate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/**
 * CertificateSource that wrap multiple CertificateSource
 * 
 * 
 * @version $Revision: 1998 $ - $Date: 2013-05-14 09:41:33 +0200 (mar., 14 mai 2013) $
 */

public class CompositeCertificateSource implements CertificateSource {

	private CertificateSource[] sources;

	/**
	 * 
	 * The default constructor for CompositeCertificateSource.
	 * 
	 * @param sources
	 */
	public CompositeCertificateSource(CertificateSource... sources) {

		ArrayList<CertificateSource> notNullArrayList = new ArrayList<CertificateSource>();
		for (CertificateSource certificateSource : sources) {

			if (certificateSource != null) {

				notNullArrayList.add(certificateSource);
			}
		}
		this.sources = notNullArrayList.toArray(new CertificateSource[notNullArrayList.size()]);
	}

	@Override
	public List<CertificateAndContext> getCertificateBySubjectName(X500Principal subjectName) throws IOException {

		List<CertificateAndContext> list = new ArrayList<CertificateAndContext>();
		for (CertificateSource source : sources) {

			List<CertificateAndContext> internal = source.getCertificateBySubjectName(subjectName);
			if (internal != null) {

				list.addAll(internal);
			}
		}
		return list;
	}
}
