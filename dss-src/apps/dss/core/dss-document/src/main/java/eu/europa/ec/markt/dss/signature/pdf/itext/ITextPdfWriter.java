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

import java.io.IOException;
import java.io.OutputStream;
import java.util.Calendar;


import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDeveloperExtension;
import com.lowagie.text.pdf.PdfIndirectReference;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfStamper;

import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfReader;
import eu.europa.ec.markt.dss.signature.pdf.PdfStream;
import eu.europa.ec.markt.dss.signature.pdf.PdfWriter;

class ITextPdfWriter implements PdfWriter {

	private PdfStamper wrapped;

	ITextPdfWriter(PdfReader reader, OutputStream output) throws IOException {
		try {
			this.wrapped = new PdfStamper(((ITextPdfReader) reader).wrapped,
					output, '\0', true);
		} catch (DocumentException e) {
			throw new IOException(e);
		}
	}

	@Override
	public void addToDict(PdfDict container, String key, PdfArray array) throws IOException {
		ITextPdfArray a = (ITextPdfArray) array;
		PdfIndirectReference ref = getPdfIndirectReference();
		wrapped.getWriter().addToBody(a.wrapped, ref, false);
		ITextPdfDict c = (ITextPdfDict) container;
		c.wrapped.put(new PdfName(key), ref);
	}

	@Override
	public void addToArray(PdfArray array, PdfStream stream) throws IOException {
		ITextPdfStream s = (ITextPdfStream) stream;
		PdfIndirectReference ref = getPdfIndirectReference();
		wrapped.getWriter().addToBody(s.wrapped, ref, false);
		ITextPdfArray a = (ITextPdfArray) array;
		a.wrapped.add(ref);
	}

	@Override
	public void addToDict(PdfDict container, String key, PdfDict dict) throws IOException {
		ITextPdfDict d = (ITextPdfDict) dict;
		PdfIndirectReference ref = getPdfIndirectReference();
		wrapped.getWriter().addToBody(d.wrapped, ref, false);
		ITextPdfDict c = (ITextPdfDict) container;
		c.wrapped.put(new PdfName(key), ref);
	}

	@Override
	public void addToDict(PdfDict container, String key, Calendar cal)
			throws IOException {
		ITextPdfDict c = (ITextPdfDict) container;
		c.wrapped.put(new PdfName(key), new PdfDate(cal));
	}
	
	private PdfIndirectReference getPdfIndirectReference() {
		return wrapped.getWriter().getPdfIndirectReference();
	}

	private void addDeveloperExtension(String prefix, String baseversion,
			int extensionLevel) {
		PdfDeveloperExtension de = new PdfDeveloperExtension(
				new PdfName(prefix), new PdfName(baseversion), extensionLevel);
		wrapped.getWriter().addDeveloperExtension(de);
	}

	@Override
	public void close() throws IOException {

		// /Extensions<</ADBE<</BaseVersion/1.7/ExtensionLevel 5>>>>
		addDeveloperExtension("ADBE", "1.7", 5);
		wrapped.getWriter().addToBody(wrapped.getReader().getCatalog(),
				wrapped.getReader().getCatalog().getIndRef());

		try {
			wrapped.close();
		} catch (DocumentException e) {
			throw new IOException(e);
		}
	}

}
