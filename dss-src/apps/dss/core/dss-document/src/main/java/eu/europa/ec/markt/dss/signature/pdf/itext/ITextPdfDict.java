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

package eu.europa.ec.markt.dss.signature.pdf.itext;

import java.util.logging.Logger;

import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfObject;

import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;

public class ITextPdfDict implements PdfDict {

	private static final Logger LOGGER = Logger.getLogger(ITextPdfDict.class
			.getName());

	PdfDictionary wrapped;

	public ITextPdfDict(PdfDictionary wrapped) {
		if (wrapped == null) {
			throw new IllegalArgumentException();
		}
		this.wrapped = wrapped;
	}

	ITextPdfDict(String dictionaryType) {
		if (dictionaryType != null) {
			wrapped = new PdfDictionary(new PdfName(dictionaryType));
		} else {
			wrapped = new PdfDictionary();
		}
	}

	@Override
	public PdfDict getAsDict(String name) {
		PdfDictionary asDict = wrapped.getAsDict(new PdfName(name));
		if (asDict == null) {
			return null;
		} else {
			return new ITextPdfDict(asDict);
		}
	}

	@Override
	public PdfArray getAsArray(String name) {
		com.lowagie.text.pdf.PdfArray asArray = wrapped.getAsArray(new PdfName(
				name));
		if (asArray == null) {
			return null;
		} else {
			return new ITextPdfArray(asArray);
		}
	}

	@Override
	public boolean hasANameWithValue(String name, String value) {
		PdfName asName = wrapped.getAsName(new PdfName(name));
		if (asName == null) {
			LOGGER.info("No value with name " + name);
			return false;
		}

		PdfName asValue = new PdfName(value);
		boolean r = asName.equals(asValue);
		LOGGER.info("Comparison of " + asName + "(" + asName.getClass() + ")"
				+ " and " + asValue + " : " + r);
		return r;
	}

	@Override
	public byte[] get(String name) {
		PdfObject val = wrapped.get(new PdfName(name));
		if (val == null) {
			return null;
		}
		return val.getBytes();
	}

}
