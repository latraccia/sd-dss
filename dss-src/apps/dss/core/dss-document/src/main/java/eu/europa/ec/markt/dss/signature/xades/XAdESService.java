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

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.ProfileParameters;
import eu.europa.ec.markt.dss.signature.ProfileParameters.Operation;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.SignatureProfile;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;

/**
 * XAdES implementation of DocumentSignatureService
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class XAdESService implements DocumentSignatureService {

   private TSPSource tspSource;

   private CertificateVerifier certificateVerifier;

   static {

      org.apache.xml.security.Init.init();
   }

   @Override
   public void setCertificateVerifier(CertificateVerifier certificateVerifier) {

      this.certificateVerifier = certificateVerifier;
   }

   @Override
   public void setTspSource(TSPSource tspSource) {

      this.tspSource = tspSource;
   }

   private XAdESProfileBES getSigningProfile(final SignatureParameters parameters) {

      if (parameters.getSignatureFormat() == null) {

         throw new DSSException("Signature format cannot be null. Please set this parameter within SignatureParameters object.");
      }
      switch (parameters.getSignatureFormat()) {
      case XAdES_BES:
         return new XAdESProfileBES();
      case XAdES_EPES:
      default:
         return new XAdESProfileEPES();
      }
   }

   /**
    * 
    * The choice of profile according to the passed parameter.
    * 
    * @param parameters
    * @return
    */
   private SignatureExtension getExtensionProfile(final SignatureParameters parameters) {

      switch (parameters.getSignatureFormat()) {
      case XAdES_BES:
      case XAdES_EPES:
         return null;
      case XAdES_T:
         XAdESProfileT extensionT = new XAdESProfileT();
         extensionT.setTspSource(tspSource);
         return extensionT;
      case XAdES_C:
         XAdESProfileC extensionC = new XAdESProfileC();
         extensionC.setTspSource(tspSource);
         extensionC.setCertificateVerifier(certificateVerifier);
         return extensionC;
      case XAdES_X:
         XAdESProfileX extensionX = new XAdESProfileX();
         extensionX.setTspSource(tspSource);
         extensionX.setCertificateVerifier(certificateVerifier);
         return extensionX;
      case XAdES_XL:
         XAdESProfileXL extensionXL = new XAdESProfileXL();
         extensionXL.setTspSource(tspSource);
         extensionXL.setCertificateVerifier(certificateVerifier);
         return extensionXL;
      case XAdES_A:
         XAdESProfileA extensionA = new XAdESProfileA();
         extensionA.setTspSource(tspSource);
         extensionA.setCertificateVerifier(certificateVerifier);
         return extensionA;
      default:
         throw new DSSException("Unsupported signature format " + parameters.getSignatureFormat());
      }
   }

   /*
    * (non-Javadoc)
    * 
    * @see
    * eu.europa.ec.markt.dss.signature.DocumentSignatureService#toBeSigned(eu.europa.ec.markt.dss.signature.Document,
    * eu.europa.ec.markt.dss.signature.SignatureParameters)
    */
   @Override
   public InputStream toBeSigned(DSSDocument document, SignatureParameters parameters) throws DSSException {

      XAdESProfileBES profile = getSigningProfile(parameters);
      InputStream is = profile.getSignedInfoStream(document, parameters);
      parameters.getContext().setProfile(profile);
      return is;
   }

   /*
    * (non-Javadoc)
    * 
    * 
    * @param document - document to sign
    * 
    * @see
    * eu.europa.ec.markt.dss.signature.DocumentSignatureService#signDocument(eu.europa.ec.markt.dss.signature.Document,
    * eu.europa.ec.markt.dss.signature.SignatureParameters, byte[])
    */
   @Override
   public DSSDocument signDocument(final DSSDocument document, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {

      parameters.getContext().setOperationKind(Operation.SIGNING);
      SignatureProfile profile;
      ProfileParameters context = parameters.getContext();
      if (context.getProfile() != null) {

         profile = context.getProfile();
      } else {

         profile = getSigningProfile(parameters);
      }
      DSSDocument signedDoc = profile.signDocument(document, parameters, signatureValue);
      SignatureExtension extension = getExtensionProfile(parameters);
      if (extension != null) {

         return extension.extendSignatures(signedDoc, parameters);
      } else {

         return signedDoc;
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

      parameters.getContext().setOperationKind(Operation.SIGNING);

      XAdESProfileBES profile = getSigningProfile(parameters);
      final InputStream signedInfo = profile.getSignedInfoStream(document, parameters);
      parameters.getContext().setProfile(profile);

      if (parameters.getSigningToken() == null) {

         throw new DSSException("SigningToken is null, the connection through available API to the SSCD must be set.");
      }
      byte[] signatureValue;
      try {

         signatureValue = parameters.getSigningToken().sign(signedInfo, parameters.getDigestAlgorithm(), parameters.getPrivateKeyEntry());
      } catch (NoSuchAlgorithmException e) {

         throw new DSSException("The digest algorythm is not supported: " + parameters.getDigestAlgorithm(), e);
      } catch (IOException e) {

         throw new DSSException("Signed info input stream read error.", e);
      }
      return signDocument(document, parameters, signatureValue);
   }

   /*
    * (non-Javadoc)
    * 
    * @see
    * eu.europa.ec.markt.dss.signature.DocumentSignatureService#extendDocument(eu.europa.ec.markt.dss.signature.Document
    * , eu.europa.ec.markt.dss.signature.Document, eu.europa.ec.markt.dss.signature.SignatureParameters)
    */
   @Override
   public DSSDocument extendDocument(DSSDocument document, SignatureParameters parameters) throws DSSException {

      parameters.getContext().setOperationKind(Operation.EXTENDING);
      SignatureExtension extension = getExtensionProfile(parameters);
      if (extension != null) {

         return extension.extendSignatures(document, parameters);
      }
      throw new DSSException("Cannot extend to " + parameters.getSignatureFormat().name());
   }

   /*
    * (non-Javadoc)
    * 
    * @see
    * eu.europa.ec.markt.dss.signature.DocumentSignatureService#extendDocument(eu.europa.ec.markt.dss.signature.Document
    * , eu.europa.ec.markt.dss.signature.Document, eu.europa.ec.markt.dss.signature.SignatureParameters)
    */
   @Override
   public DSSDocument extendDocument(DSSDocument document, DSSDocument originalDocument, SignatureParameters parameters) throws IOException {

      parameters.getContext().setOperationKind(Operation.EXTENDING);
      SignatureExtension extension = getExtensionProfile(parameters);
      if (extension != null) {

         try {

            return extension.extendSignatures(document, parameters);
         } catch (DSSException e) {

            throw new IOException(e);
         }
      }
      // TODO: (Bob) It should perhaps be notified that the level requested does not exist?
      return document;
   }
}
