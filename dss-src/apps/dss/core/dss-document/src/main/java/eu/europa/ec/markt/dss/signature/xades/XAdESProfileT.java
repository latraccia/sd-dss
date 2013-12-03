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

package eu.europa.ec.markt.dss.signature.xades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.JAXBException;
import javax.xml.crypto.dsig.XMLSignature;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;

import eu.europa.ec.markt.dss.exception.CannotFetchDataException;
import eu.europa.ec.markt.dss.exception.ConfigurationException;
import eu.europa.ec.markt.dss.exception.ConfigurationException.MSG;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.ProfileParameters;
import eu.europa.ec.markt.dss.signature.ProfileParameters.Operation;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;
import eu.europa.ec.markt.tsl.jaxb.xades.EncapsulatedPKIDataType;
import eu.europa.ec.markt.tsl.jaxb.xades.XAdESTimeStampType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.CanonicalizationMethodType;

/**
 * -T profile of XAdES signature
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class XAdESProfileT extends ExtensionBuilder implements SignatureExtension {

   private static final Logger LOG = Logger.getLogger(XAdESProfileT.class.getName());

   /*
    * The object encapsulating the Time Stamp Protocol needed to create the level -T, of the signature
    */
   protected TSPSource tspSource;

   /**
    * The default constructor for XAdESProfileT.
    * 
    */
   public XAdESProfileT() {

      super();
      LOG.info("XAdESProfileT new instance created.");
   }

   /*
    * (non-Javadoc)
    * 
    * @see eu.europa.ec.markt.dss.signature.SignatureExtension#extendSignature(java.lang.Object,
    * eu.europa.ec.markt.dss.signature.Document, eu.europa.ec.markt.dss.signature.Document,
    * eu.europa.ec.markt.dss.signature.SignatureParameters)
    */
   @Deprecated
   @Override
   public DSSDocument extendSignature(Object signatureId, DSSDocument document, SignatureParameters parameters) throws IOException {

      try {
         return extendSignatures(document, parameters);
      } catch (DSSException e) {

         throw new IOException(e);
      }

   }

    /**
     * Creates JAXB XAdES TimeStamp object representation. The time stamp token is obtained from TSP source
     *
     * @param digestAlgorithm
     * @param timestampCanonicalizationMethod
     * @param digestValue
     * @return
     * @throws DSSException
     */
   protected XAdESTimeStampType createXAdESTimeStampType(final DigestAlgorithm digestAlgorithm, final String timestampCanonicalizationMethod, final byte[] digestValue) throws DSSException {

      try {

         final TimeStampResponse resp = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);
         final byte[] timeStampToken = resp.getTimeStampToken().getEncoded();

         final EncapsulatedPKIDataType encapsulatedTimeStamp = xadesFactory.createEncapsulatedPKIDataType();
         encapsulatedTimeStamp.setValue(timeStampToken);
         encapsulatedTimeStamp.setId("time-stamp-token-" + UUID.randomUUID().toString());

         final CanonicalizationMethodType c14nMethod = xmlDSigFactory.createCanonicalizationMethodType();
         c14nMethod.setAlgorithm(timestampCanonicalizationMethod);

         final XAdESTimeStampType xadesTimeStamp = xadesFactory.createXAdESTimeStampType();
         xadesTimeStamp.setCanonicalizationMethod(c14nMethod);
         xadesTimeStamp.setId("time-stamp-" + UUID.randomUUID().toString());
         xadesTimeStamp.getEncapsulatedTimeStampOrXMLTimeStamp().add(encapsulatedTimeStamp);
         return xadesTimeStamp;
      } catch (CannotFetchDataException e) {

         throw new DSSException("Error durring the creation of the XAdES timestamp!", e);
      } catch (IOException e) {

         throw new DSSException("Error durring the creation of the XAdES timestamp!", e);
      }
   }

   /*
    * This method extends the existing signatures.
    * 
    * @see
    * eu.europa.ec.markt.dss.signature.SignatureExtension#extendSignatures(eu.europa.ec.markt.dss.signature.Document,
    * eu.europa.ec.markt.dss.signature.SignatureParameters)
    */
   @Override
   public DSSDocument extendSignatures(DSSDocument document, SignatureParameters params) throws DSSException {

      if (this.tspSource == null) {

         throw new ConfigurationException(MSG.CONFIGURE_TSP_SERVER);
      }
      this.params = params;
      final ProfileParameters context = params.getContext();
      InputStream input = null;
      try {

         if (LOG.isLoggable(Level.INFO)) LOG.info("====> Extending: " + (document.getName() == null ? "IN MEMORY DOCUMENT" : document.getName()));
         input = document.openStream();
         final Document domDoc = ExtensionBuilder.documentBuilder.parse(input);

         final NodeList signatureNodeList = domDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
         if (signatureNodeList.getLength() == 0) {

            throw new RuntimeException("Impossible to perform the extension of the signature, the document is not signed.");
         }

         // In the case of the enveloped signature we have a specific treatment:<br>
         // we will just extend the signature that is being created (during creation process)
         String signatureId = null;
         if (Operation.SIGNING.equals(context.getOperationKind()) && SignaturePackaging.ENVELOPED.equals(params.getSignaturePackaging())) {

            signatureId = "sigId-" + params.getDeterministicId();
         }
         for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

            final Element signatureDOM = (Element) signatureNodeList.item(ii);
            if (signatureId != null && !signatureId.equals(signatureDOM.getAttribute("Id"))) {

               continue;
            }
            xadesSignature = new XAdESSignature(signatureDOM);
            extendSignatureTag();
         }
         DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
         DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
         LSSerializer writer = impl.createLSSerializer();

         ByteArrayOutputStream buffer = new ByteArrayOutputStream();
         LSOutput output = impl.createLSOutput();
         output.setByteStream(buffer);
         writer.write(domDoc, output);

         return new InMemoryDocument(buffer.toByteArray());
      } catch (ClassCastException e) {
         throw new DSSException(e);
      } catch (ClassNotFoundException e) {
         throw new DSSException(e);
      } catch (InstantiationException e) {
         throw new DSSException(e);
      } catch (IllegalAccessException e) {
         throw new DSSException(e);
      } catch (IOException e) {
         throw new DSSException(e);
      } catch (SAXException e) {
         throw new DSSException(e);
      } finally {
         DSSUtils.closeQuietly(input);
      }
   }

   /**
    * Extends the signature to a desired level. This method is overridden by other profiles.<br>
    * For -T profile adds the SignatureTimeStamp element which contains a single HashDataInfo element that refers to the
    * ds:SignatureValue element of the [XMLDSIG] signature. The timestamp token is obtained from TSP source.<br>
    * Adds <SignatureTimeStamp> segment into <UnsignedSignatureProperties> element.
    * 
    * @throws DSSException
    */
   protected void extendSignatureTag() throws DSSException {

      try {

         // We ensure that all XML segments needed for the construction of the extension -T are present.
         // If a segment does not exist then it is created.
         ensureUnsignedProperties();
         ensureUnsignedSignatureProperties();

         if (!canAddExtension()) {

            // TODO: (Bob)
         }
         // The timestamp must be added only if there is no one or the extension -T is being created
         if (!xadesSignature.hasTExtension() || SignatureFormat.XAdES_T.equals(params.getSignatureFormat())) {

            final MessageDigest digest = MessageDigest.getInstance(timestampDigestAlgorithm.getName());
            final Canonicalizer c14n = Canonicalizer.getInstance(timestampCanonicalizationMethod);
            digest.update(c14n.canonicalizeSubtree(xadesSignature.getSignatureValue()));
            final XAdESTimeStampType signatureTimeStampType = createXAdESTimeStampType(timestampDigestAlgorithm, timestampCanonicalizationMethod, digest.digest());
            marshal(xadesFactory.createSignatureTimeStamp(signatureTimeStampType), xadesSignature.getUnsignedSignatureProperties());
         }
      } catch (InvalidCanonicalizerException e) {

         throw new DSSException(e);
      } catch (JAXBException e) {

         throw new DSSException(e);
      } catch (NoSuchAlgorithmException e) {

         throw new DSSException(e);
      } catch (CanonicalizationException e) {

         throw new DSSException(e);
      }
   }

   /**
    * Sets the TSP source to be used when extending the digital signature
    * 
    * @param tspSource the tspSource to set
    */
   public void setTspSource(TSPSource tspSource) {

      this.tspSource = tspSource;
   }

}
