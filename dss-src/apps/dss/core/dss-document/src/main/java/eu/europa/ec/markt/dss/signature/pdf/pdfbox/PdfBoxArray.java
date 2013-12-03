package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.ec.markt.dss.signature.pdf.PdfArray;

public class PdfBoxArray implements PdfArray {

	COSArray wrapped;

	// Retain this reference ! PDDocument must not be garbage collected
	@SuppressWarnings("unused")
	private PDDocument document;

	public PdfBoxArray() {
		wrapped = new COSArray();
	}

	public PdfBoxArray(COSArray wrapped, PDDocument document) {
		this.wrapped = wrapped;
		this.document = document;
	}

	@Override
	public int size() {
		return wrapped.size();
	}

	@Override
	public byte[] getBytes(int i) throws IOException {
		COSBase val = wrapped.get(i);
		return toBytes(val);
	}

	private byte[] toBytes(COSBase val) throws IOException {
		COSStream data = null;
		if(val instanceof COSObject) {
			COSObject o = (COSObject) val;
			if(o.getObject() instanceof COSStream) {
				data = (COSStream) o.getObject();
			}
		}
		if(data == null) {
			throw new RuntimeException("Cannot find value for " + val + " of class " + val.getClass());
		}
		return IOUtils.toByteArray(data.getFilteredStream());
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

}
