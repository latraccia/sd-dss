package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.pdf.PdfReader;

public class PdfBoxObjectFactory extends PdfObjFactory {

	@Override
	public PdfBoxArray newArray() {
		return new PdfBoxArray();
	}

	@Override
	public PdfBoxDict newDict(String dictType) {
		return new PdfBoxDict(dictType);
	}

	@Override
	public PdfBoxReader newReader(InputStream input) throws IOException {
		return new PdfBoxReader(input);
	}

	@Override
	public PdfBoxStream newStream(byte[] bytes) throws IOException {
		return new PdfBoxStream(bytes);
	}

	@Override
	public PdfBoxWriter newWriter(PdfReader reader, OutputStream output)
			throws IOException {
		return new PdfBoxWriter(((PdfBoxReader) reader).getPDDocument(), output);
	}

	@Override
	public PDFSignatureService newPAdESSignatureService() {
		return new PdfBoxSignatureService();
	}

	@Override
	public PDFSignatureService newTimestampSignatureService() {
		return new PdfBoxDocTimeStampService();
	}

}
