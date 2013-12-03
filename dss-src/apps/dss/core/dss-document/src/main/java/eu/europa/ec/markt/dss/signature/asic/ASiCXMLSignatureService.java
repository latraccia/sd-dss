/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/trunk/buildtools/src/main/resources/eclipse/dss-java-code-template.xml $
 * $Revision: 672 $
 * $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * $Author: hiedelch $
 */
package eu.europa.ec.markt.dss.signature.asic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.FileNameMap;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

/**
 * Implementation of DocumentSignatureService for ASiC-S documents.
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ASiCXMLSignatureService implements DocumentSignatureService {

   private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
   private final static String ZIP_ENTRY_MIMETYPE = "mimetype";
   private final static String ZIP_ENTRY_METAINF_SIGNATURE = "META-INF/signatures.xml";

   private final static String ASICS_EXTENSION = ".asics";
   private final static String ASICS_NS = "asic:XAdESSignatures";
   private final static String ASICS_URI = "http://uri.etsi.org/2918/v1.2.1#";

   private TSPSource tspSource;

   private CertificateVerifier certificateVerifier;

   /**
    * Creates specific XAdES signature parameters on base of the provided parameters. Forces the signature packaging to
    * DETACHED
    * 
    * @param parameters must provide signingToken, PrivateKeyEntry and date
    * @param forExtension forces signature format to XAdES_T if true otherwise to XAdES_BES
    * @return new specific instance for XAdES
    */
   private void setXAdESParams(final SignatureParameters parameters, final boolean forExtension) {

      parameters.setSignatureFormat(forExtension ? SignatureFormat.XAdES_T : SignatureFormat.XAdES_BES);
      parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
   }

   /*
    * (non-Javadoc)
    * 
    * @see eu.europa.ec.markt.dss.signature.DocumentSignatureService#digest(eu.europa .ec.markt.dss.signature.Document,
    * eu.europa.ec.markt.dss.signature.SignatureParameters)
    */
   @Deprecated
   public Digest digest(DSSDocument document, SignatureParameters parameters) throws DSSException {

      try {
         // process via signature service
         final InputStream input = toBeSigned(document, parameters);
         final byte[] data = IOUtils.toByteArray(input);

         // process the digest
         final MessageDigest digest = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
         final byte[] digestValue = digest.digest(data);

         // return a new digest
         return new Digest(DigestAlgorithm.SHA1, digestValue);
      } catch (NoSuchAlgorithmException e) {

         throw new DSSException(e);
      } catch (IOException e) {

         throw new DSSException(e);
      }
   }

   /*
    * (non-Javadoc)
    * 
    * @see
    * eu.europa.ec.markt.dss.signature.DocumentSignatureService#extendDocument(eu.europa.ec.markt.dss.signature.Document
    * , eu.europa.ec.markt.dss.signature.Document, eu.europa.ec.markt.dss.signature.SignatureParameters)
    */
   @Override
   @Deprecated
   public DSSDocument extendDocument(DSSDocument document, DSSDocument originalDocument, SignatureParameters parameters) throws IOException {

      try {

         return extendDocument(document, parameters);
      } catch (DSSException e) {

         throw new IOException(e);
      }
   }

   @Override
   public void setCertificateVerifier(CertificateVerifier certificateVerifier) {

      this.certificateVerifier = certificateVerifier;
   }

   @Override
   public void setTspSource(TSPSource tspSource) {

      this.tspSource = tspSource;
   }

   /**
    * ETSI TS 102 918 v1.2.1 (2012-02) <br />
    * <p>
    * Contents of Container ( 6.2.2 )
    * </p>
    * <ul>
    * <li>The file extension ".asics" should be used .</li>
    * <li>The root element of each signature content shall be either &lt;asic:XadESSignatures&gt; as specified in clause
    * A.5. Its the recommended format</li>
    * <li>The comment field in the ZIP header may be used to identify the type of the data object within the container.
    * <br />
    * If this field is present, it should be set with "mimetype=" followed by the mime type of the data object held in
    * the signed data object</li>
    * <li>The mimetype file can be used to support operating systems that rely on some content in specific positions in
    * a file.<br />
    * <ul>
    * <li>It has to be the first entry in the archive.</li>
    * <li>It cannot contain "Extra fields".</li>
    * <li>It cannot be compressed or encrypted inside the ZIP file</li>
    * </ul>
    * </li>
    * </ul>
    * 
    */
   @Override
   public DSSDocument signDocument(DSSDocument document, SignatureParameters parameters, byte[] signatureValue) throws DSSException {

      try {

         // Signs the document first
         setXAdESParams(parameters, false);

         final XAdESService xadesService = parameters.getContext().getXadesService();
         System.out.println("File name: " + document.getName());
         final DSSDocument signedDocument = xadesService.signDocument(document, parameters, signatureValue);

         // Creates the XAdES signature
         final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
         dbf.setNamespaceAware(true);
         final org.w3c.dom.Document xmlSignatureDoc = dbf.newDocumentBuilder().parse(signedDocument.openStream());
         final Element xmlSignatureElement = (Element) xmlSignatureDoc.removeChild(xmlSignatureDoc.getDocumentElement());

         final DocumentBuilder builder = dbf.newDocumentBuilder();
         final DOMImplementation domImpl = builder.getDOMImplementation();

         final org.w3c.dom.Document xmlXadesDoc = domImpl.createDocument(ASICS_URI, ASICS_NS, null);
         final Element xmlXadesElement = xmlXadesDoc.getDocumentElement();

         xmlXadesDoc.adoptNode(xmlSignatureElement);
         xmlXadesElement.appendChild(xmlSignatureElement);

         final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
         final ZipOutputStream outZip = new ZipOutputStream(outBytes);

         // Zip comment
         if (parameters.isAsicComment() && StringUtils.isNotEmpty(document.getName())) {

            if (!System.getProperties().containsKey("content.types.user.table")) {
               final URL contentTypeURL = this.getClass().getResource("/custom-content-types.properties");
               if (contentTypeURL != null) {
                  System.setProperty("content.types.user.table", contentTypeURL.getPath());
               }
            }

            final FileNameMap fileNameMap = URLConnection.getFileNameMap();
            final String containedFileMimeType = fileNameMap.getContentTypeFor(document.getName());
            outZip.setComment("mimetype=" + containedFileMimeType);
         }

         // Stores the ASiC mime-type
         final String aSiCMimeType = MimeType.ASICS.getCode();
         final ZipEntry entryMimetype = new ZipEntry(ZIP_ENTRY_MIMETYPE);
         entryMimetype.setMethod(ZipEntry.STORED);
         entryMimetype.setSize(aSiCMimeType.getBytes().length);
         entryMimetype.setCompressedSize(aSiCMimeType.getBytes().length);
         final CRC32 crc = new CRC32();
         crc.update(aSiCMimeType.getBytes());
         entryMimetype.setCrc(crc.getValue());
         outZip.putNextEntry(entryMimetype);
         outZip.write(aSiCMimeType.getBytes());

         // Stores the original document
         final ZipEntry entryDocument = new ZipEntry(document.getName() != null ? document.getName() : ZIP_ENTRY_DETACHED_FILE);
         outZip.setLevel(ZipEntry.DEFLATED);
         outZip.putNextEntry(entryDocument);
         IOUtils.copy(document.openStream(), outZip);

         // Stores the XAdES signature
         final ZipEntry entrySignature = new ZipEntry(ZIP_ENTRY_METAINF_SIGNATURE);
         outZip.putNextEntry(entrySignature);
         TransformerFactory.newInstance().newTransformer().transform(new DOMSource(xmlXadesDoc), new StreamResult(outZip));

         // Finishes the ZIP (with implicit finish/flush)
         outZip.close();

         // return the new document = ASiC-S
         return new InMemoryDocument(outBytes.toByteArray(), document.getName() != null ? document.getName() + ASICS_EXTENSION : null, MimeType.ASICS);
      } catch (Exception e) {

         throw new DSSException(e);
      }

   }

   /*
    * (non-Javadoc)
    * 
    * @see eu.europa.ec.markt.dss.signature.DocumentSignatureService#toBeSigned(
    * eu.europa.ec.markt.dss.signature.Document, eu.europa.ec.markt.dss.signature.SignatureParameters)
    */
   @Override
   public InputStream toBeSigned(DSSDocument document, SignatureParameters parameters) throws DSSException {

      setXAdESParams(parameters, false);
      final XAdESService xadesService = parameters.getContext().getXadesService();
      return xadesService.toBeSigned(document, parameters);
   }

   @Override
   public DSSDocument signDocument(DSSDocument document, SignatureParameters params) throws DSSException {

      final InputStream toBeSignedData = toBeSigned(document, params);
      if (params.getSigningToken() == null) {

         throw new DSSException("SigningToken is null, the connection through available API to the SSCD must be set.");
      }
      byte[] signatureValue;
      try {

         signatureValue = params.getSigningToken().sign(toBeSignedData, params.getDigestAlgorithm(), params.getPrivateKeyEntry());
      } catch (NoSuchAlgorithmException e) {

         throw new DSSException("The digest algorythm is not supported: " + params.getDigestAlgorithm(), e);
      } catch (IOException e) {

         throw new DSSException("Signed info input stream read error.", e);
      }
      return signDocument(document, params, signatureValue);
   }

   @Override
   public DSSDocument extendDocument(DSSDocument document, SignatureParameters parameters) throws DSSException {

      if (parameters.getSignatureFormat() != SignatureFormat.ASiC_S_T) {

         throw new DSSException("Unsupported signature format " + parameters.getSignatureFormat());
      }
      try {

         SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
         validator.setExternalContent(parameters.getOriginalDocument());

         final XAdESService service = parameters.getContext().getXadesService();
         service.setCertificateVerifier(certificateVerifier);
         service.setTspSource(tspSource);

         setXAdESParams(parameters, true);
         final DSSDocument signedDocument = service.extendDocument(validator.getDocument(), parameters);

         final ByteArrayOutputStream output = new ByteArrayOutputStream();
         final ZipOutputStream zip = new ZipOutputStream(output);

         final ZipInputStream input = new ZipInputStream(document.openStream());
         ZipEntry entry = null;
         while ((entry = input.getNextEntry()) != null) {

            ZipEntry newEntry = new ZipEntry(entry.getName());
            if (ZIP_ENTRY_METAINF_SIGNATURE.equals(entry.getName())) {

               zip.putNextEntry(newEntry);
               IOUtils.copy(signedDocument.openStream(), zip);
            } else {

               zip.putNextEntry(newEntry);
               IOUtils.copy(input, zip);
            }

         }
         zip.close();
         return new InMemoryDocument(output.toByteArray());
      } catch (IOException e) {

         throw new DSSException(e);
      }
   }

}
