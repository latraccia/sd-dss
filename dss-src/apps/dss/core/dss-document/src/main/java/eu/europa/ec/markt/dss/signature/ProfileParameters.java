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

package eu.europa.ec.markt.dss.signature;

import eu.europa.ec.markt.dss.signature.xades.SignatureBuilder;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;

/**
 * This class This class manages the internal variables used in the process of creating a signature and which allow to
 * accelerate the generation.<br>
 * ! This class must be derived to also take into account other formats then XAdES
 * 
 */
public class ProfileParameters {

	private SignatureProfile profile;

	/**
	 * Returns the current Profile used to generate the signature or its extension
	 * 
	 * @return
	 */
	public SignatureProfile getProfile() {

		return profile;
	}

	/**
	 * Sets the current Profile used to generate the signature or its extension
	 * 
	 * @return
	 */
	public void setProfile(SignatureProfile profile) {

		this.profile = profile;
	}

	/*
	 * The builder used to create the signature structure. Currently used only for XAdES.
	 */
	private SignatureBuilder builder;

	public SignatureBuilder getBuilder() {

		return builder;
	}

	public void setBuilder(SignatureBuilder builder) {

		this.builder = builder;
	}

	/*
	 * The type of operation to perform.
	 */
	public static enum Operation {

		SIGNING, EXTENDING
	};

	/*
	 * Indicates the type of the operation to be done
	 */
	Operation operationKind;

	public Operation getOperationKind() {

		return operationKind;
	}

	public void setOperationKind(Operation operationKind) {

		this.operationKind = operationKind;
	}

	/*
	 * Used in ASiC signature generation process
	 */
	private XAdESService xadesService;

	public XAdESService getXadesService() {

		if (xadesService == null) {

			xadesService = new XAdESService();
		}
		return xadesService;
	}

	public void setXadesService(XAdESService xadesService) {

		this.xadesService = xadesService;
	}
}
