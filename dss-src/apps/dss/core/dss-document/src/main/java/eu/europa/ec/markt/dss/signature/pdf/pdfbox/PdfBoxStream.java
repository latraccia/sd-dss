package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.IOException;

import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.io.RandomAccessBuffer;

import eu.europa.ec.markt.dss.signature.pdf.PdfStream;

public class PdfBoxStream implements PdfStream {

	COSStream wrapped;

	public PdfBoxStream(byte[] bytes) throws IOException {
		RandomAccessBuffer storage = new RandomAccessBuffer();
		this.wrapped = new COSStream(storage);
		this.wrapped.createUnfilteredStream().write(bytes);
	}

}
