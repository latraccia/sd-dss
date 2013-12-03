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

package eu.europa.ec.markt.dss.validation.ades;

import eu.europa.ec.markt.dss.validation.ocsp.OfflineOCSPSource;

/**
 * The advanced signature contains a list of OCSPResp that were needed to validate the signature. This class is a basic
 * skeleton that is able to retrieve the needed OCSPResp from a list. The child needs to retrieve the list of wrapped
 * OCSPResp.
 * 
 *
 * @version $Revision: 1437 $ - $Date: 2012-11-23 14:19:32 +0100 (ven., 23 nov. 2012) $
 */

public abstract class SignatureOCSPSource extends OfflineOCSPSource {

}
