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

package eu.europa.ec.markt.dss.signature.pades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.cades.CAdESProfileT;
import eu.europa.ec.markt.dss.signature.cades.PreComputedContentSigner;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

/**
 * PAdES implementation of the DocumentSignatureService
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class PAdESServiceV2 implements DocumentSignatureService {

   private static final Logger LOG = Logger.getLogger(PAdESServiceV2.class.getName());

   private TSPSource tspSource;

   private CertificateVerifier certificateVerifier;

   @Override
   public void setTspSource(TSPSource tspSource) {

      this.tspSource = tspSource;
   }

   @Override
   public void setCertificateVerifier(CertificateVerifier certificateVerifier) {

      this.certificateVerifier = certificateVerifier;
   }

   private PAdESProfileLTV getExtensionProfile(SignatureParameters parameters) {

      switch (parameters.getSignatureFormat()) {
      case PAdES_BES:
      case PAdES_EPES:
         return null;
      case PAdES_LTV:
         PAdESProfileLTV profile = new PAdESProfileLTV();
         profile.setCertificateVerifier(certificateVerifier);
         profile.setTspSource(tspSource);
         return profile;
      default:
         throw new IllegalArgumentException("Signature format '" + parameters.getSignatureFormat() + "' not supported");
      }
   }

   @Override
   public InputStream toBeSigned(DSSDocument document, SignatureParameters parameters) throws DSSException {

      try {

         final PAdESProfileEPES padesProfile = new PAdESProfileEPES();

         final SignatureAlgorithm signatureAlgo = parameters.getSignatureAlgorithm();
         final PreComputedContentSigner contentSigner = new PreComputedContentSigner(signatureAlgo.getJAVAId());
         final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

         final PDFSignatureService pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
         final byte[] messageDigest = pdfSignatureService.digest(document.openStream(), parameters);
         if (LOG.isLoggable(Level.FINE)) LOG.fine("Calculated digest on byterange " + Hex.encodeHexString(messageDigest));

         final CMSSignedDataGenerator generator = padesProfile.createCMSSignedDataGenerator(contentSigner, digestCalculatorProvider, parameters, messageDigest);

         final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);

         generator.generate(content, false);

         return new ByteArrayInputStream(contentSigner.getByteOutputStream().toByteArray());
      } catch (CMSException e) {

         throw new DSSException(e);
      } catch (IOException e) {

         throw new DSSException(e);
      }

   }

   @Deprecated
   public Digest digest(DSSDocument document, SignatureParameters parameters) throws IOException {

      byte[] digestValue = null;
      MessageDigest dig;
      try {
         dig = MessageDigest.getInstance(parameters.getDigestAlgorithm().getName());
         digestValue = dig.digest(IOUtils.toByteArray(toBeSigned(document, parameters)));
         return new Digest(parameters.getDigestAlgorithm(), digestValue);
      } catch (NoSuchAlgorithmException e) {
         throw new RuntimeException("No " + parameters.getDigestAlgorithm() + " algorithm available ?!");
      } catch (DSSException e) {

         throw new IOException(e);
      }

   }

   @Override
   public DSSDocument signDocument(DSSDocument document, SignatureParameters parameters, byte[] signatureValue) throws DSSException {

      try {

         final PAdESProfileEPES padesProfile = new PAdESProfileEPES();

         final SignatureAlgorithm signatureAlgo = parameters.getSignatureAlgorithm();
         final PreComputedContentSigner contentSigner = new PreComputedContentSigner(signatureAlgo.getJAVAId(), signatureValue);
         final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

         final PDFSignatureService pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
         final byte[] messageDigest = pdfSignatureService.digest(document.openStream(), parameters);
         if (LOG.isLoggable(Level.FINE)) LOG.fine("Calculated digest on byterange " + Hex.encodeHexString(messageDigest));

         final CMSSignedDataGenerator generator = padesProfile.createCMSSignedDataGenerator(contentSigner, digestCalculatorProvider, parameters, messageDigest);

         final CMSProcessableByteArray content = new CMSProcessableByteArray(messageDigest);

         CMSSignedData data = generator.generate(content, false);
         if (tspSource != null) {

            final CAdESProfileT cadesProfileT = new CAdESProfileT();
            cadesProfileT.setSignatureTsa(tspSource);
            data = cadesProfileT.extendCMSSignedData(data, null, parameters);
         }

         final ByteArrayOutputStream output = new ByteArrayOutputStream();

         pdfSignatureService.sign(document.openStream(), data.getEncoded(), output, parameters);
         output.close();

         DSSDocument doc = null;

         if (StringUtils.isEmpty(document.getName())) {

            doc = new InMemoryDocument(output.toByteArray());
         } else {

            doc = new InMemoryDocument(output.toByteArray(), document.getName());
         }

         final PAdESProfileLTV extension = getExtensionProfile(parameters);
         if (extension != null) {

            return extension.extendSignatures(doc, null, parameters);
         } else {

            return doc;
         }
      } catch (CMSException e) {

         throw new DSSException(e);
      } catch (IOException e) {

         throw new DSSException(e);
      }
   }

   @Override
   public DSSDocument extendDocument(DSSDocument document, DSSDocument originalDocument, SignatureParameters parameters) throws IOException {

      PAdESProfileLTV extension = getExtensionProfile(parameters);
      if (extension != null) {
         return extension.extendSignatures(document, originalDocument, parameters);
      } else {
         return document;
      }
   }

   @Override
   public DSSDocument signDocument(DSSDocument document, SignatureParameters parameters) throws DSSException {

      throw new DSSException("Not yet implemented for this type of signature.");
   }

   @Override
   public DSSDocument extendDocument(DSSDocument document, SignatureParameters parameters) throws DSSException {

      throw new DSSException("Not yet implemented for this type of signature.");
   }
}
