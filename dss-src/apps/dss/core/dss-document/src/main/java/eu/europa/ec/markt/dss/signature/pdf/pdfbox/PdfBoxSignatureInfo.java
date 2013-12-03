package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.IOException;
import java.io.InputStream;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.pdfwriter.COSFilterInputStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.tls.Certificate;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.validation.cades.CAdESSignature;

public class PdfBoxSignatureInfo implements PdfSignatureInfo {

   private PDSignature signature;

   @SuppressWarnings("unused")
   private PDDocument document;

   private InputStream inputStream;

   private CAdESSignature cades;

   @SuppressWarnings("unused")
   private boolean verified;

   public PdfBoxSignatureInfo(PDDocument document, PDSignature signature, InputStream inputStream) throws IOException {

      try {
         this.signature = signature;
         this.inputStream = inputStream;

         PdfBoxDict sign = new PdfBoxDict(signature.getDictionary(), document);

         final COSArray array = (COSArray) signature.getDictionary().getDictionaryObject("ByteRange");

         final byte[] cms = sign.get("Contents");
         System.out.println(cms.length);
         System.out.println(array);

         cades = new CAdESSignature(cms);

      } catch (CMSException e) {
         throw new IOException(e);
      }

   }

   @Override
   public boolean verify() throws SignatureException {

      COSFilterInputStream stream = null;
      try {

         stream = new COSFilterInputStream(inputStream, signature.getByteRange());

         return cades.checkIntegrity(new InMemoryDocument(stream.toByteArray()));

      } catch (Exception e) {
         throw new RuntimeException(e);
      } finally {

         DSSUtils.closeQuietly(stream);
      }
   }

   public X509Certificate getSigningCertificate() {
      return cades.getSigningCertificate();
   }

   public Certificate[] getCertificateChain() {
      return cades.getCertificates().toArray(new Certificate[cades.getCertificates().size()]);
   }

   @Override
   public String getLocation() {
      return signature.getLocation();
   }

   @Override
   public Date getSigningDate() {
      return signature.getSignDate() != null ? signature.getSignDate().getTime() : null;
   }

}
