package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.IOException;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;

public class PdfBoxDict implements PdfDict {

	COSDictionary wrapped;
	
	private PDDocument document;

	public PdfBoxDict(COSDictionary wrapped, PDDocument document) {
		this.wrapped = wrapped;
		this.document = document;
	}

	public PdfBoxDict(String type) {
		wrapped = new COSDictionary();
		if (type != null) {
			wrapped.setItem("Type", COSName.getPDFName(type));
		}
	}

	@Override
	public PdfDict getAsDict(String name) {
		COSDictionary dict = (COSDictionary) wrapped.getDictionaryObject(name);
		if(dict == null) {
			return null;
		}
		return new PdfBoxDict(dict, document);
	}

	@Override
	public PdfArray getAsArray(String name) {
		COSArray array = (COSArray) wrapped.getDictionaryObject(name);
		if(array == null) {
			return null;
		}
		return new PdfBoxArray(array, document);
	}

	@Override
	public boolean hasANameWithValue(String name, String value) {
		COSName pdfName = (COSName) wrapped.getDictionaryObject(name);
		if (pdfName == null) {
			return false;
		}
		return pdfName.getName().equals(value);
	}

	@Override
	public byte[] get(String name) throws IOException {
		COSBase val = (COSBase) wrapped.getDictionaryObject(name);
		if (val == null) {
			return null;
		}
		if(val instanceof COSString) {
			return ((COSString)val).getBytes();
		}
		throw new IOException(name + " was expected to be a COSString element but was " + val.getClass() + " : " + val);
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

}
