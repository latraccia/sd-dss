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

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

/**
 * Base class for extending a CAdESSignature.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public abstract class CAdESSignatureExtension implements SignatureExtension {

   private static final Logger LOG = Logger.getLogger(CAdESSignatureExtension.class.getName());

   protected TSPSource signatureTsa;

   /**
    * @return the TSA used for the signature-time-stamp attribute
    */
   public TSPSource getSignatureTsa() {

      return signatureTsa;
   }

   /**
    * @param signatureTsa the signatureTsa to set
    */
   public void setSignatureTsa(TSPSource signatureTsa) {

      this.signatureTsa = signatureTsa;
   }

   public DSSDocument extendSignatures(DSSDocument document, SignatureParameters parameters) throws DSSException {

      InputStream input = null;
      try {

         input = document.openStream();
         CMSSignedData signedData = new CMSSignedData(input);
         SignerInformationStore signerStore = signedData.getSignerInfos();
         ArrayList<SignerInformation> siArray = new ArrayList<SignerInformation>();
         Iterator<?> infos = signerStore.getSigners().iterator();
         while (infos.hasNext()) {

            SignerInformation si = (SignerInformation) infos.next();
            try {

               siArray.add(extendCMSSignature(signedData, si, parameters));
            } catch (IOException ex) {

               LOG.severe("Exception when extending signature");
               siArray.add(si);
            }
         }
         SignerInformationStore newSignerStore = new SignerInformationStore(siArray);
         CMSSignedData extended = CMSSignedData.replaceSigners(signedData, newSignerStore);
         return new InMemoryDocument(extended.getEncoded());
      } catch (Exception e) {

         throw new DSSException("Cannot parse CMS data", e);
      } finally {

         DSSUtils.closeQuietly(input);
      }
   }

   public DSSDocument extendSignature(Object signatureId, DSSDocument document, DSSDocument originalData, SignatureParameters parameters) throws IOException {

      final SignerId toExtendId = (SignerId) signatureId;
      InputStream input = null;
      try {

         input = document.openStream();
         final CMSSignedData signedData = new CMSSignedData(input);
         final SignerInformationStore signerStore = signedData.getSignerInfos();
         final ArrayList<SignerInformation> siArray = new ArrayList<SignerInformation>();
         final Iterator<?> infos = signerStore.getSigners().iterator();
         while (infos.hasNext()) {

            final SignerInformation si = (SignerInformation) infos.next();
            if (si.getSID().equals(toExtendId)) {

               try {

                  siArray.add(extendCMSSignature(signedData, si, parameters));
               } catch (IOException ex) {

                  LOG.severe("Exception when extending signature");
                  siArray.add(si);
               }
            }
         }
         final SignerInformationStore newSignerStore = new SignerInformationStore(siArray);
         final CMSSignedData extended = CMSSignedData.replaceSigners(signedData, newSignerStore);
         return new InMemoryDocument(extended.getEncoded());
      } catch (CMSException e) {
         throw new IOException("Cannot parse CMS data", e);
      } finally {

         DSSUtils.closeQuietly(input);
      }
   }

   abstract protected SignerInformation extendCMSSignature(CMSSignedData signedData, SignerInformation si, SignatureParameters parameters) throws IOException;

   /**
    * Computes an attribute containing a time-stamp token of the provided data, from the provided TSA using the
    * provided. The hashing is performed by the method using the specified algorithm and a BouncyCastle provider.
    * 
    * @param signedData
    * @throws Exception
    */
   protected Attribute getTimeStampAttribute(ASN1ObjectIdentifier oid, TSPSource tsa, AlgorithmIdentifier digestAlgorithm, byte[] messageImprint) {

      try {

         MessageDigest dig = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName(), new BouncyCastleProvider());
         byte[] toTimeStamp = dig.digest(messageImprint);

         TimeStampResponse tsresp = tsa.getTimeStampResponse(DigestAlgorithm.SHA1, toTimeStamp);

         TimeStampToken tstoken = tsresp.getTimeStampToken();

         if (tstoken == null) {
            throw new NullPointerException("The TimeStampToken returned for the signature time stamp was empty.");
         }

         Attribute signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Object.fromByteArray(tstoken.getEncoded())));

         return signatureTimeStamp;
      } catch (IOException e) {
         throw new RuntimeException(e);
      } catch (NoSuchAlgorithmException e) {
         throw new RuntimeException(e);
      }
   }

   /**
    * 
    * @param signedData
    * @return
    */
   @SuppressWarnings("unchecked")
   public CMSSignedData extendCMSSignedData(CMSSignedData signedData, DSSDocument originalData, SignatureParameters parameters) {

      SignerInformationStore signerStore = signedData.getSignerInfos();

      ArrayList<SignerInformation> siArray = new ArrayList<SignerInformation>();

      Iterator<SignerInformation> infos = signerStore.getSigners().iterator();
      while (infos.hasNext()) {

         SignerInformation si = infos.next();
         try {
            siArray.add(extendCMSSignature(signedData, si, parameters));
         } catch (IOException ex) {
            LOG.severe("Exception when extending signature");
            siArray.add(si);
         }
      }

      SignerInformationStore newSignerStore = new SignerInformationStore(siArray);
      return CMSSignedData.replaceSigners(signedData, newSignerStore);

   }

}
