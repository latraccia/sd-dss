package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Calendar;
import java.util.UUID;

import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfStream;
import eu.europa.ec.markt.dss.signature.pdf.PdfWriter;

public class PdfBoxWriter implements PdfWriter {

	PDDocument document;

	private OutputStream output;

	private FileInputStream tempInput;

	private FileOutputStream tempOutput;

	private File tempDocumentOut;

	public PdfBoxWriter(PDDocument document, OutputStream output)
			throws IOException {

		this.document = document;
		try {
			this.output = output;

			File tempDocumentIn = new File("target/copyoffile.pdf");
			tempOutput = new FileOutputStream(tempDocumentIn);
			document.save(tempOutput);
			tempOutput.close();

			tempInput = new FileInputStream(tempDocumentIn);
			tempDocumentOut = new File("target/copyoffileout.pdf");
			tempOutput = new FileOutputStream(tempDocumentOut);
			IOUtils.copy(tempInput, tempOutput);
			tempInput.close();

			tempInput = new FileInputStream(tempDocumentIn);

		} catch (COSVisitorException e) {
			throw new IOException(e);
		}

	}

	@Override
	public void close() throws IOException {
		try {
			PdfBoxCOSWriterDSS.saveIncremental(document, tempInput, tempOutput,
					UUID.randomUUID().toString());
			tempOutput.close();
			tempInput.close();

			tempInput = new FileInputStream(tempDocumentOut);
			IOUtils.copy(tempInput, output);
			tempInput.close();
		} catch (COSVisitorException e) {
			throw new IOException(e);
		}
	}

	@Override
	public void addToArray(PdfArray container, PdfStream stream)
			throws IOException {
		PdfBoxArray c = (PdfBoxArray) container;
		PdfBoxStream s = (PdfBoxStream) stream;
		c.wrapped.add(s.wrapped);
		c.wrapped.setNeedToBeUpdate(true);
	}

	@Override
	public void addToDict(PdfDict container, String key, PdfArray array)
			throws IOException {
		PdfBoxDict c = (PdfBoxDict) container;
		PdfBoxArray a = (PdfBoxArray) array;
		c.wrapped.setItem(key, a.wrapped);
		c.wrapped.setNeedToBeUpdate(true);
	}

	@Override
	public void addToDict(PdfDict container, String key, PdfDict dict)
			throws IOException {
		PdfBoxDict c = (PdfBoxDict) container;
		PdfBoxDict d = (PdfBoxDict) dict;
		c.wrapped.setItem(key, d.wrapped);
		c.wrapped.setNeedToBeUpdate(true);
	}
	
	@Override
	public void addToDict(PdfDict container, String key, Calendar cal)
			throws IOException {
		PdfBoxDict c = (PdfBoxDict) container;
		c.wrapped.setDate(key, cal);
		c.wrapped.setNeedToBeUpdate(true);
	}

}
