package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.Calendar;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.SignatureValidationCallback;

public class PdfBoxSignatureService implements PDFSignatureService {

	@Override
	public byte[] digest(InputStream pdfData, SignatureParameters parameters)
			throws IOException {

		File file = File.createTempFile("raw", ".pdf");
		FileOutputStream output = new FileOutputStream(file);
		IOUtils.copy(pdfData, output);
		output.close();

		File signed = File.createTempFile("raw", "-signed.pdf");
		FileInputStream in2 = new FileInputStream(file);
		output = new FileOutputStream(signed);
		IOUtils.copy(in2, output);
		in2.close();

		PDDocument doc = PDDocument.load(file);

		// create signature dictionary
		PDSignature signature = new PDSignature();
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
		// subfilter for basic and PAdES Part 2 signatures
		signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);

		// the signing date, needed for valid signature
		Calendar cal = Calendar.getInstance();
		cal.setTime(parameters.getSigningDate());
		signature.setSignDate(cal);

		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(parameters.getDigestAlgorithm()
					.getName());

			// register signature dictionary and sign interface
			SignatureInterface si = new SignatureInterface() {

				@Override
				public byte[] sign(InputStream content)
						throws org.apache.pdfbox.exceptions.SignatureException,
						IOException {
					byte[] b = new byte[4096];
					int count = -1;
					while ((count = content.read(b)) > 0) {
						digest.update(b, 0, count);
						System.out.write(b, 0, count);
						System.out.println(count);
					}
					return new byte[0];
				}
			};
			doc.addSignature(signature, si);

			FileInputStream in3 = new FileInputStream(signed);
			System.out
					.println("****************************************** Digest");
			PdfBoxCOSWriterDSS
					.saveIncremental(doc, in3, output, Hex
							.encodeHexString(MessageDigest.getInstance("MD5")
									.digest(parameters.getSigningDate()
											.toString().getBytes())));
			byte[] digest2 = digest.digest();
			System.out.println("Dihest " + Hex.encodeHexString(digest2));
			System.out.println("******************************************");
			in3.close();
			output.close();

			return digest2;
			// write incremental (only for signing purpose)
		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			file.delete();
			signed.delete();
			doc.close();
		}
	}

	@Override
	public void sign(InputStream pdfData, final byte[] signatureValue,
			OutputStream signedStream, SignatureParameters parameters)
			throws IOException {

		File file = new File("target/pdfboxtest.pdf");
		FileOutputStream output = new FileOutputStream(file);
		IOUtils.copy(pdfData, output);
		output.close();

		File signed = new File(file.getParent(), file.getName() + "-signed.pdf");
		FileInputStream in2 = new FileInputStream(file);
		output = new FileOutputStream(signed);
		IOUtils.copy(in2, output);
		in2.close();

		PDDocument doc = PDDocument.load(file);

		// create signature dictionary
		PDSignature signature = new PDSignature();
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
		// subfilter for basic and PAdES Part 2 signatures
		signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);

		// the signing date, needed for valid signature
		Calendar cal = Calendar.getInstance();
		cal.setTime(parameters.getSigningDate());
		signature.setSignDate(cal);

		final MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(parameters.getDigestAlgorithm()
					.getName());

			// register signature dictionary and sign interface
			SignatureInterface si = new SignatureInterface() {

				@Override
				public byte[] sign(InputStream content)
						throws org.apache.pdfbox.exceptions.SignatureException,
						IOException {
					byte[] b = new byte[4096];
					int count = -1;
					while ((count = content.read(b)) > 0) {
						digest.update(b, 0, count);
						System.out.write(b, 0, count);
						System.out.println(count);
					}
					return signatureValue;
				}
			};
			doc.addSignature(signature, si);

			FileInputStream in3 = new FileInputStream(signed);
			System.out
					.println("****************************************** Signature");
			PdfBoxCOSWriterDSS
					.saveIncremental(doc, in3, output, Hex
							.encodeHexString(MessageDigest.getInstance("MD5")
									.digest(parameters.getSigningDate()
											.toString().getBytes())));
			System.out.println("Le digest étzit "
					+ Hex.encodeHexString(digest.digest()));
			System.out.println("******************************************");
			in3.close();
			output.close();

			in3 = new FileInputStream(signed);
			IOUtils.copy(in3, signedStream);
			in3.close();

		} catch (Exception e) {
			throw new IOException(e);
		} finally {
			file.delete();
			signed.delete();
			doc.close();
		}

	}

	@Override
	public void validateSignatures(InputStream input,
			SignatureValidationCallback callback) throws IOException {

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		IOUtils.copy(input, buffer);

		PDDocument doc = PDDocument.load(new ByteArrayInputStream(buffer
				.toByteArray()));
		PdfDict catalog = new PdfBoxDict(doc.getDocumentCatalog()
				.getCOSDictionary(), doc);
		PdfDict outerCatalog = catalog;

		PDSignature signature = doc.getSignatureDictionary();
		if (signature == null) {
			return;
		}

		PdfBoxSignatureInfo info = new PdfBoxSignatureInfo(doc, signature, new ByteArrayInputStream(
				buffer.toByteArray()));
		
		callback.validate(catalog, outerCatalog, info.getSigningCertificate(), info.getSigningDate(), null,
				new PdfBoxDict(signature.getDictionary(), doc),
				info);
	}

}
