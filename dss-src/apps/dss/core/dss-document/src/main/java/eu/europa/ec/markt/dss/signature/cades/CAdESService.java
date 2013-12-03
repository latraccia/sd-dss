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

package eu.europa.ec.markt.dss.signature.cades;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.logging.Logger;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.provider.SignatureInterceptorProvider;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

/**
 * CAdES implementation of DocumentSignatureService
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class CAdESService implements DocumentSignatureService {

   private static final Logger LOG = Logger.getLogger(CAdESService.class.getName());

   private TSPSource tspSource;

   private CertificateVerifier verifier;

   static {

      SignatureInterceptorProvider provider = new SignatureInterceptorProvider();
      Security.addProvider(provider);
   }

   /**
    * The default constructor for CAdESService.
    */
   public CAdESService() {

      Security.addProvider(new BouncyCastleProvider());
   }

   @Override
   public void setTspSource(TSPSource tspSource) {

      this.tspSource = tspSource;
   }

   @Override
   public void setCertificateVerifier(CertificateVerifier verifier) {

      this.verifier = verifier;
   }

   /**
    * Because some information are stored in the profile, a profile is not Thread-safe. The software must create one for
    * each request.
    * 
    * @return A new instance of signatureProfile corresponding to the parameters.
    */
   private CAdESProfileBES getSigningProfile(SignatureParameters parameters) {

      switch (parameters.getSignatureFormat()) {
      case CAdES_BES:
         return new CAdESProfileBES();
      case CAdES_EPES:
      default:
         return new CAdESProfileEPES();
      }
   }

   private CAdESSignatureExtension getExtensionProfile(SignatureParameters parameters) {

      switch (parameters.getSignatureFormat()) {
      case CAdES_BES:
      case CAdES_EPES:
         return null;
      case CAdES_T:
         CAdESProfileT extensionT = new CAdESProfileT();
         extensionT.setSignatureTsa(tspSource);
         return extensionT;
      case CAdES_C:
         CAdESProfileC extensionC = new CAdESProfileC();
         extensionC.setSignatureTsa(tspSource);
         extensionC.setCertificateVerifier(verifier);
         return extensionC;
      case CAdES_X:
         CAdESProfileX extensionX = new CAdESProfileX();
         extensionX.setSignatureTsa(tspSource);
         extensionX.setExtendedValidationType(1);
         extensionX.setCertificateVerifier(verifier);
         return extensionX;
      case CAdES_XL:
         CAdESProfileXL extensionXL = new CAdESProfileXL();
         extensionXL.setSignatureTsa(tspSource);
         extensionXL.setExtendedValidationType(1);
         extensionXL.setCertificateVerifier(verifier);
         return extensionXL;
      case CAdES_A:
         CAdESProfileA extensionA = new CAdESProfileA();
         extensionA.setSignatureTsa(tspSource);
         extensionA.setCertificateVerifier(verifier);
         extensionA.setExtendedValidationType(1);
         return extensionA;
      default:
         throw new RuntimeException("Unsupported signature format " + parameters.getSignatureFormat());
      }
   }

   @Deprecated
   public Digest digest(DSSDocument document, SignatureParameters parameters) throws DSSException {

      byte[] digestValue = null;
      MessageDigest dig;
      try {

         dig = MessageDigest.getInstance(parameters.getDigestAlgorithm().getName());
         digestValue = dig.digest(IOUtils.toByteArray(toBeSigned(document, parameters)));
         return new Digest(parameters.getDigestAlgorithm(), digestValue);
      } catch (NoSuchAlgorithmException e) {

         throw new DSSException(e);
      } catch (IOException e) {

         throw new DSSException(e);
      }
   }

   @Override
   public InputStream toBeSigned(DSSDocument document, SignatureParameters parameters) throws DSSException {

      final SignaturePackaging packaging = parameters.getSignaturePackaging();
      if (!packaging.equals(SignaturePackaging.ENVELOPING) && !packaging.equals(SignaturePackaging.DETACHED)) {

         throw new IllegalArgumentException("Unsupported signature packaging " + packaging);
      }
      InputStream input = null;
      try {

         final SignatureAlgorithm signatureAlgo = SignatureAlgorithm.getAlgorithm(parameters.getEncryptionAlgorithm(), parameters.getDigestAlgorithm());
         final PreComputedContentSigner pccs = new PreComputedContentSigner(signatureAlgo.getJAVAId());
         final DigestCalculatorProvider dcp = new BcDigestCalculatorProvider();
         final CMSSignedDataGenerator generator = createCMSSignedDataGenerator(pccs, dcp, parameters, getSigningProfile(parameters), false, null);

         input = document.openStream();
         final CMSProcessableByteArray content = new CMSProcessableByteArray(IOUtils.toByteArray(input));
         generator.generate(content, !packaging.equals(SignaturePackaging.DETACHED));
         return new ByteArrayInputStream(pccs.getByteOutputStream().toByteArray());
      } catch (Exception e) {

         throw new DSSException(e);
      } finally {

         DSSUtils.closeQuietly(input);
      }
   }

   /**
    * {@inheritDoc}
    */
   @Override
   public DSSDocument signDocument(DSSDocument document, SignatureParameters parameters, byte[] signatureValue) throws DSSException {

      final SignaturePackaging packaging = parameters.getSignaturePackaging();
      if (!packaging.equals(SignaturePackaging.ENVELOPING) && !packaging.equals(SignaturePackaging.DETACHED)) {

         throw new IllegalArgumentException("Unsupported signature packaging " + packaging);
      }
      InputStream input = null;
      try {

         final SignatureAlgorithm signatureAlgo = SignatureAlgorithm.getAlgorithm(parameters.getEncryptionAlgorithm(), parameters.getDigestAlgorithm());
         final PreComputedContentSigner pccs = new PreComputedContentSigner(signatureAlgo.getJAVAId(), signatureValue);
         final DigestCalculatorProvider dcp = new BcDigestCalculatorProvider();
         final CMSSignedDataGenerator generator = createCMSSignedDataGenerator(pccs, dcp, parameters, getSigningProfile(parameters), true, null);

         input = document.openStream();
         final CMSProcessableByteArray content = new CMSProcessableByteArray(IOUtils.toByteArray(input));
         final CMSSignedData data = generator.generate(content, !packaging.equals(SignaturePackaging.DETACHED));
         DSSDocument signedDocument = new CMSSignedDocument(data);
         /*
          * Extend the file if needed
          */
         CAdESSignatureExtension extension = getExtensionProfile(parameters);
         if (extension != null) {

            parameters.setOriginalDocument(document);
            signedDocument = extension.extendSignatures(new CMSSignedDocument(data), parameters);
         }
         return signedDocument;
      } catch (CMSException e) {

         throw new DSSException(e);
      } catch (IOException e) {

         throw new DSSException(e);
      } finally {
         DSSUtils.closeQuietly(input);
      }
   }

   /**
    * Signs the document in the single operation
    * 
    * @param document - document to sign
    * @param parameters
    * @return
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws DSSException
    */
   @Override
   public DSSDocument signDocument(DSSDocument document, SignatureParameters parameters) throws DSSException {

      SignaturePackaging packaging = parameters.getSignaturePackaging();
      if (!packaging.equals(SignaturePackaging.ENVELOPING) && !packaging.equals(SignaturePackaging.DETACHED)) {

         throw new IllegalArgumentException("Unsupported signature packaging " + packaging);
      }
      SignatureTokenConnection token = parameters.getSigningToken();
      if (token == null) {

         throw new IllegalArgumentException("SigningToken is null, the connection through available API to the SSCD must be set.");
      }
      InputStream input = null;
      try {

         input = toBeSigned(document, parameters);
         byte[] signatureValue = token.sign(input, parameters.getDigestAlgorithm(), parameters.getPrivateKeyEntry());
         return signDocument(document, parameters, signatureValue);
      } catch (NoSuchAlgorithmException e) {

         throw new DSSException("The digest algorythm is not supported: " + parameters.getDigestAlgorithm(), e);
      } catch (IOException e) {

         throw new DSSException("Signed info input stream read error.", e);
      } finally {

         DSSUtils.closeQuietly(input);
      }
   }

   /**
    * Add a signature to the already CMS signed data document.
    * 
    * @param _signedDocument
    * @param parameters
    * @param signatureValue
    * @return
    * @throws IOException
    */
   public DSSDocument addASignatureToDocument(DSSDocument _signedDocument, SignatureParameters parameters, byte[] signatureValue) throws IOException {

      if (parameters.getSignaturePackaging() != SignaturePackaging.ENVELOPING) {

         throw new IllegalArgumentException("Unsupported signature packaging " + parameters.getSignaturePackaging());
      }

      InputStream input = null;
      try {

         input = _signedDocument.openStream();
         CMSSignedData originalSignedData = new CMSSignedData(input);

         final SignatureAlgorithm signatureAlgo = SignatureAlgorithm.getAlgorithm(parameters.getEncryptionAlgorithm(), parameters.getDigestAlgorithm());
         PreComputedContentSigner cs = new PreComputedContentSigner(signatureAlgo.getJAVAId(), signatureValue);
         DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

         CMSSignedDataGenerator generator = createCMSSignedDataGenerator(cs, digestCalculatorProvider, parameters, getSigningProfile(parameters), true, originalSignedData);

         if (originalSignedData == null || originalSignedData.getSignedContent().getContent() == null) {
            throw new RuntimeException("Cannot retrieve orignal content");
         }

         byte[] octetString = (byte[]) originalSignedData.getSignedContent().getContent();

         CMSProcessableByteArray content = new CMSProcessableByteArray(octetString);

         CMSSignedData data = generator.generate(content, true);

         DSSDocument signedDocument = new CMSSignedDocument(data);

         /*
          * Extend the file if needed
          */
         CAdESSignatureExtension extension = getExtensionProfile(parameters);
         if (extension != null) {

            parameters.setOriginalDocument(null);
            signedDocument = extension.extendSignatures(new CMSSignedDocument(data), parameters);
         }
         return signedDocument;
      } catch (CMSException e) {

         throw new DSSException(e);
      } finally {

         DSSUtils.closeQuietly(input);
      }
   }

   @Override
   public DSSDocument extendDocument(DSSDocument document, DSSDocument originalDocument, SignatureParameters parameters) throws IOException {

      CAdESSignatureExtension extension = getExtensionProfile(parameters);
      if (extension != null) {

         /*
          * In case of -A extension, when eContent is missing, we should provide the original document
          */
         parameters.setOriginalDocument(originalDocument);
         return extension.extendSignatures(document, parameters);
      } else {
         LOG.info("No extension for " + parameters.getSignatureFormat());
      }
      return document;
   }

   /*
    * (non-Javadoc)
    * 
    * @see
    * eu.europa.ec.markt.dss.signature.DocumentSignatureService#extendDocument(eu.europa.ec.markt.dss.signature.Document
    * , eu.europa.ec.markt.dss.signature.SignatureParameters)
    */
   @Override
   public DSSDocument extendDocument(DSSDocument document, SignatureParameters parameters) throws DSSException {

      CAdESSignatureExtension extension = getExtensionProfile(parameters);
      if (extension != null) {

         return extension.extendSignatures(document, parameters);
      } else {
         LOG.info("No extension for " + parameters.getSignatureFormat());
      }
      return document;
   }

   private CMSSignedDataGenerator createCMSSignedDataGenerator(ContentSigner contentSigner, DigestCalculatorProvider digestCalculatorProvider, SignatureParameters parameters,
            CAdESProfileBES cadesProfile, boolean includeUnsignedAttributes, CMSSignedData originalSignedData) throws IOException {

      try {

         CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

         X509Certificate signerCertificate = parameters.getSigningCertificate();

         X509CertificateHolder certHolder = new X509CertificateHolder(signerCertificate.getEncoded());

         SignerInfoGeneratorBuilder sigInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);

         sigInfoGeneratorBuilder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(cadesProfile.getSignedAttributes(parameters))));

         sigInfoGeneratorBuilder.setUnsignedAttributeGenerator(new SimpleAttributeTableGenerator((includeUnsignedAttributes) ? new AttributeTable(cadesProfile.getUnsignedAttributes(parameters))
                  : null));

         SignerInfoGenerator sigInfoGen = sigInfoGeneratorBuilder.build(contentSigner, certHolder);

         generator.addSignerInfoGenerator(sigInfoGen);
         if (originalSignedData != null) {
            generator.addSigners(originalSignedData.getSignerInfos());
         }

         Collection<X509Certificate> certs = new ArrayList<X509Certificate>();
         certs.add(parameters.getSigningCertificate());

         if (parameters.getCertificateChain() != null) {
            for (X509Certificate c : parameters.getCertificateChain()) {
               if (!c.getSubjectX500Principal().equals(parameters.getSigningCertificate().getSubjectX500Principal())) {
                  certs.add(c);
               }
            }
         }

         JcaCertStore certStore = new JcaCertStore(certs);
         generator.addCertificates(certStore);
         if (originalSignedData != null) {
            generator.addCertificates(originalSignedData.getCertificates());
         }

         return generator;

      } catch (CMSException e) {
         throw new IOException(e);
      } catch (CertificateEncodingException e) {
         throw new IOException(e);
      } catch (OperatorCreationException e) {
         throw new IOException(e);
      }
   }
}
