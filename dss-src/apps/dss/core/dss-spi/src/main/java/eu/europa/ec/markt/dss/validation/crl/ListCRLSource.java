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

package eu.europa.ec.markt.dss.validation.crl;

import java.security.cert.X509CRL;
import java.util.List;

/**
 * Encapsulates a list of X509CRLs.
 * 
 * @version $Revision: 1961 $ - $Date: 2013-05-10 06:46:46 +0200 (ven., 10 mai 2013) $
 */

public class ListCRLSource extends OfflineCRLSource {

	private List<X509CRL> list;

	/**
	 * The default constructor for ListCRLSource.
	 * 
	 * @param list
	 */
	public ListCRLSource(List<X509CRL> list) {

		this.list = list;
	}

	@Override
	public List<X509CRL> getContainedCRLs() {

		return list;
	}

}
