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

package eu.europa.ec.markt.dss.validation.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;

import eu.europa.ec.markt.dss.exception.CannotFetchDataException;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder to retrieve the OCSP response.
 * 
 * 
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class OnlineOCSPSource implements OCSPSource {

   private static final Logger LOG = Logger.getLogger(OnlineOCSPSource.class.getName());

   private HTTPDataLoader httpDataLoader;

   static {

      // TODO by meyerfr: shouldn't that be done once e.g. in an environment
      // initializer?
      Security.addProvider(new BouncyCastleProvider());
   }

   /**
    * Create an OCSP source The default constructor for OnlineOCSPSource.
    */
   public OnlineOCSPSource() {

   }

   /**
    * Set the HTTPDataLoader to use for querying the OCSP server.
    * 
    * @param httpDataLoader
    */
   public void setHttpDataLoader(HTTPDataLoader httpDataLoader) {

      this.httpDataLoader = httpDataLoader;
   }

   @Override
   public BasicOCSPResp getOCSPResponse(X509Certificate certificate, X509Certificate issuerCertificate) throws IOException {

      if (httpDataLoader == null) {

         throw new DSSException("The HTTPDataLoader must be set. Use setHttpDataLoader method first.");
      }
      try {

         final String ocspUri = getAccessLocation(certificate, X509ObjectIdentifiers.ocspAccessMethod);
         if (LOG.isLoggable(Level.INFO)) LOG.info("OCSP URI: " + ocspUri);
         if (ocspUri == null) {

            return null;
         }
         final CertificateID certId = new CertificateID(CertificateID.HASH_SHA1, issuerCertificate, certificate.getSerialNumber());
         final OCSPReqGenerator ocspReqGenerator = new OCSPReqGenerator();
         ocspReqGenerator.addRequest(certId);
         final OCSPReq ocspReq = ocspReqGenerator.generate();
         final byte[] ocspReqData = ocspReq.getEncoded();
         final InputStream ocspRespStream = httpDataLoader.post(ocspUri, new ByteArrayInputStream(ocspReqData));
         final OCSPResp ocspResp = new OCSPResp(ocspRespStream);
         try {

            return (BasicOCSPResp) ocspResp.getResponseObject();
         } catch (NullPointerException e) {
            /**
             * Encountered a case when the OCSPResp is initialised with a null OCSP response... (and there are no
             * nullity checks in the OCSPResp implementation)
             */
         }
      } catch (CannotFetchDataException e) {

         LOG.severe("OCSP error: CannotFetchDataException: " + e.getMessage());
      } catch (OCSPException e) {

         LOG.severe("OCSP error: " + e.getMessage());
      }
      return null;
   }

   private String getAccessLocation(X509Certificate certificate, DERObjectIdentifier accessMethod) throws IOException {

      final byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(X509Extension.authorityInfoAccess.getId());
      if (null == authInfoAccessExtensionValue) {

         return null;
      }
      ASN1InputStream ais1 = null;
      ASN1InputStream ais2 = null;
      try {

         final ByteArrayInputStream bais = new ByteArrayInputStream(authInfoAccessExtensionValue);
         ais1 = new ASN1InputStream(bais);
         final DEROctetString oct = (DEROctetString) (ais1.readObject());
         ais2 = new ASN1InputStream(oct.getOctets());
         final AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess((ASN1Sequence) ais2.readObject());

         final AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
         for (AccessDescription accessDescription : accessDescriptions) {

            if (LOG.isLoggable(Level.FINE)) LOG.fine("Access method: " + accessDescription.getAccessMethod());
            final boolean correctAccessMethod = accessDescription.getAccessMethod().equals(accessMethod);
            if (!correctAccessMethod) {

               continue;
            }
            final GeneralName gn = accessDescription.getAccessLocation();
            if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {

               if (LOG.isLoggable(Level.FINE)) LOG.fine("Not a uniform resource identifier");
               continue;
            }
            final DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.getDERObject()).getObject();
            final String accessLocation = str.getString();
            if (LOG.isLoggable(Level.FINE)) LOG.fine("Access location: " + accessLocation);
            return accessLocation;
         }
         return null;
      } finally {

         DSSUtils.closeQuietly(ais1);
         DSSUtils.closeQuietly(ais2);
      }
   }

   /**
    * Gives back the OCSP URI meta-data found within the given X509 certificate.
    * 
    * @param certificate the X509 certificate.
    * @return the OCSP URI, or <code>null</code> if the extension is not present.
    * @throws MalformedURLException
    */
   public String getOCSPUri(X509Certificate certificate) {

      try {

         return getAccessLocation(certificate, X509ObjectIdentifiers.ocspAccessMethod);
      } catch (IOException e) {

         LOG.fine("OCSP location cannot be foud: " + e.getMessage());
      }
      return null;
   }
}
