package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.IOException;
import java.io.InputStream;

import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.ec.markt.dss.signature.pdf.PdfReader;

public class PdfBoxReader implements PdfReader {

	private PDDocument wrapped;

	public PdfBoxReader(InputStream inputstream) throws IOException {
		wrapped = PDDocument.load(inputstream);
	}

	@Override
	public PdfBoxDict getCatalog() {
		return new PdfBoxDict(wrapped.getDocumentCatalog().getCOSDictionary(), wrapped);
	}

	PDDocument getPDDocument() {
		return wrapped;
	}

}
