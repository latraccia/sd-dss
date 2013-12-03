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

package eu.europa.ec.markt.dss.ws.report;

import eu.europa.ec.markt.dss.validation.report.SignatureLevelX;
import eu.europa.ec.markt.dss.validation.report.TimestampVerificationResult;

import java.util.ArrayList;
import java.util.List;

/**
 * Wrap data of a SignatureLevelX. Used to expose the information in the Webservice.
 * 
 * 
 * @version $Revision: 2408 $ - $Date: 2013-08-20 08:11:34 +0200 (mar., 20 août 2013) $
 */

public class WSSignatureLevelX {

   private String levelReached;
   private List<WSTimestampVerificationResult> signatureAndRefsTimestampsVerification;
   private List<WSTimestampVerificationResult> referencesTimestampsVerification;

   /**
    * The default constructor for WSSignatureLevelX.
    */
   public WSSignatureLevelX() {
   }

   /**
    * 
    * The default constructor for WSSignatureLevelX.
    * 
    * @param level
    */
   public WSSignatureLevelX(SignatureLevelX level) {
      if (level.getLevelReached() != null) {
         levelReached = level.getLevelReached().getStatus().toString();
      }
      signatureAndRefsTimestampsVerification = new ArrayList<WSTimestampVerificationResult>();
      if (level.getSignatureAndRefsTimestampsVerification() != null) {
         for (TimestampVerificationResult result : level.getSignatureAndRefsTimestampsVerification()) {
            signatureAndRefsTimestampsVerification.add(new WSTimestampVerificationResult(result));
         }
      }
      if (level.getReferencesTimestampsVerification() != null) {
         referencesTimestampsVerification = new ArrayList<WSTimestampVerificationResult>();
         for (TimestampVerificationResult result : level.getReferencesTimestampsVerification()) {
            referencesTimestampsVerification.add(new WSTimestampVerificationResult(result));
         }
      }
   }

   /**
    * @return the levelReached
    */
   public String getLevelReached() {
      return levelReached;
   }

   /**
    * @param levelReached the levelReached to set
    */
   public void setLevelReached(String levelReached) {
      this.levelReached = levelReached;
   }

   /**
    * @return the signatureAndRefsTimestampsVerification
    */
   public List<WSTimestampVerificationResult> getSignatureAndRefsTimestampsVerification() {
      return signatureAndRefsTimestampsVerification;
   }

   /**
    * @param signatureAndRefsTimestampsVerification the signatureAndRefsTimestampsVerification to set
    */
   public void setSignatureAndRefsTimestampsVerification(List<WSTimestampVerificationResult> signatureAndRefsTimestampsVerification) {
      this.signatureAndRefsTimestampsVerification = signatureAndRefsTimestampsVerification;
   }

   /**
    * @return the referencesTimestampsVerification
    */
   public List<WSTimestampVerificationResult> getReferencesTimestampsVerification() {
      return referencesTimestampsVerification;
   }

   /**
    * @param referencesTimestampsVerification the referencesTimestampsVerification to set
    */
   public void setReferencesTimestampsVerification(List<WSTimestampVerificationResult> referencesTimestampsVerification) {
      this.referencesTimestampsVerification = referencesTimestampsVerification;
   }

}
