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

import com.lowagie.text.pdf.PRStream;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfReader;

class ITextPdfArray implements eu.europa.ec.markt.dss.signature.pdf.PdfArray {

	PdfArray wrapped;

	ITextPdfArray() {
		this(new PdfArray());
	}

	ITextPdfArray(PdfArray wrapped) {
		this.wrapped = wrapped;
	}

	@Override
	public byte[] getBytes(int i) throws IOException {
		return PdfReader.getStreamBytes((PRStream) wrapped.getAsStream(i));
	}

	@Override
	public int size() {
		return wrapped.size();
	}

}
