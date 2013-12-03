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

package eu.europa.ec.markt.dss.validation.cades;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.validation.ades.SignatureCertificateSource;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.StoreException;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * CertificateSource that retrieve items from a CAdES Signature
 * 
 * 
 * @version $Revision: 2411 $ - $Date: 2013-08-26 07:01:25 +0200 (lun., 26 août 2013) $
 */

public class CAdESCertificateSource extends SignatureCertificateSource {

   private static final Logger LOG = Logger.getLogger(CAdESCertificateSource.class.getName());

   private CMSSignedData cmsSignedData;
   private SignerId signerId;
   private boolean onlyExtended = true;

   /**
    * The default constructor for CAdESCertificateSource.
    * 
    * @param encodedCMS
    * @throws CMSException
    */
   public CAdESCertificateSource(CMSSignedData cms) {

      this(cms, ((SignerInformation) cms.getSignerInfos().getSigners().iterator().next()).getSID(), false);
   }

   /**
    * The default constructor for CAdESCertificateSource.
    * 
    * @param encodedCMS
    * @throws CMSException
    */
   public CAdESCertificateSource(CMSSignedData cms, SignerId id, boolean onlyExtended) {

      this.cmsSignedData = cms;
      this.signerId = id;
      this.onlyExtended = onlyExtended;
   }

   @Override
   @SuppressWarnings("unchecked")
   public List<X509Certificate> getCertificates() {

      List<X509Certificate> list = new ArrayList<X509Certificate>();
      try {

         String info_ = "";
         if (!onlyExtended) {

            for (X509CertificateHolder certHolder : (Collection<X509CertificateHolder>) cmsSignedData.getCertificates().getMatches(null)) {

               X509Certificate c = new X509CertificateObject(certHolder.toASN1Structure());
               if (!list.contains(c)) {

                  list.add(c);
                  if (LOG.isLoggable(Level.INFO)) info_ += CertificateIdentifier.getId(c) + ", ";
               }
            }
         }
         // Add certificates in CAdES-XL certificate-values inside SignerInfo attribute if present
         SignerInformation si = cmsSignedData.getSignerInfos().get(signerId);
         if (si != null && si.getUnsignedAttributes() != null && si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certValues) != null) {

            DERSequence seq = (DERSequence) si.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certValues).getAttrValues().getObjectAt(0);
            for (int i = 0; i < seq.size(); i++) {

               X509CertificateStructure cs = X509CertificateStructure.getInstance(seq.getObjectAt(i));
               X509Certificate c = new X509CertificateObject(cs);
               if (!list.contains(c)) {

                  list.add(c);
                  if (LOG.isLoggable(Level.INFO)) info_ += CertificateIdentifier.getId(c) + " xl, ";
               }
            }
         }
         if (LOG.isLoggable(Level.INFO)) LOG.info("CAdESCertificateSource: Certificate(s) in collection: " + info_);
      } catch (CertificateParsingException e) {

         throw new RuntimeException(e);
      } catch (StoreException e) {

         throw new RuntimeException(e);
      }
      return list;
   }
}
