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

package eu.europa.ec.markt.dss.validation.report;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;

import java.util.logging.Logger;

/**
 * Validation information about a Signature.
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureInformation {

   private static final Logger LOG = Logger.getLogger(SignatureInformation.class.getName());

   public SignatureInformation() {
   }

   /**
    * QC: Qualified Certificate QES: Qualified Electronic Signature AdES: Advanced Electronic Signatures
    * 
    */
   @XmlEnum
   public enum FinalConclusion {

      @XmlEnumValue("QES")
      QES, @XmlEnumValue("AdES_QC")
      AdES_QC, @XmlEnumValue("AdES")
      AdES, @XmlEnumValue("UNDETERMINED")
      UNDETERMINED
   }

   @XmlElement
   private SignatureVerification signatureVerification;
   @XmlElement
   private CertPathRevocationAnalysis certPathRevocationAnalysis;

   private SignatureLevelAnalysis signatureLevelAnalysis;
   @XmlElement
   private QualificationsVerification qualificationsVerification;
   @XmlElement
   private QCStatementInformation qcStatementInformation;

   @XmlElement
   private FinalConclusion finalConclusion;
   @XmlElement
   private String finalConclusionComment;

   private String signatureId;

   public String getSignatureId() {
      return signatureId;
   }

   public void setSignatureId(String signatureId) {
      this.signatureId = signatureId;
   }

   /**
    * defines that a (whatever) strategy can be used to determine the final conclusion regarding the
    * SignatureInformation
    */
   private static interface FinalConclusionStrategy {
      /**
       * determines the final conclusion
       * 
       * @param sigInfo the data to assess
       * @return the result
       */
      Outcome assess(final SignatureInformation sigInfo);

      /**
       * a simple class to hold the outcome attributes of the strategy
       */
      public static class Outcome {
         /**
          * the final result
          */
         private FinalConclusion result;
         /**
          * an optional comment (as i18n key)
          */
         private String comment;

         /**
          * constructor
          */
         public Outcome() {
         }

         /**
          * the final result
          * 
          * @return the value
          */
         public FinalConclusion getResult() {
            return result;
         }

         /**
          * the final result
          * 
          * @param result the value
          */
         public void setResult(final FinalConclusion result) {
            this.result = result;
         }

         /**
          * the optional comment (as i18n key)
          * 
          * @return the value
          */
         public String getComment() {
            return comment;
         }

         /**
          * the optional comment (as i18n key)
          * 
          * @param comment the value
          */
         public void setComment(final String comment) {
            this.comment = comment;
         }
      }
   }

   /**
    * a "default" implementation following the Functional Analysis of DSS
    */
   private static class DefaultFinalConclusionStrategy implements FinalConclusionStrategy {

      /**
       * rows[TL cases lines, CERT cases columns]
       */
      //@formatter:off
        private final static FinalConclusion[][] MATRIX = {
        { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.AdES_QC, FinalConclusion.AdES, FinalConclusion.QES,     FinalConclusion.AdES },
        { FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.AdES, FinalConclusion.QES,     FinalConclusion.AdES },
        { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.AdES, FinalConclusion.AdES_QC, FinalConclusion.AdES },
        { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.AdES_QC, FinalConclusion.AdES, FinalConclusion.QES,     FinalConclusion.AdES },
        { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.AdES_QC, FinalConclusion.AdES, FinalConclusion.QES,     FinalConclusion.AdES },
        { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.AdES_QC, FinalConclusion.AdES, FinalConclusion.QES,     FinalConclusion.AdES },
        { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.AdES_QC, FinalConclusion.AdES, FinalConclusion.QES,     FinalConclusion.AdES },
        { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.QES,     FinalConclusion.AdES_QC, FinalConclusion.AdES, FinalConclusion.QES,     FinalConclusion.AdES } };
  			//@formatter:on

      /**
       * {@inheritDoc}
       */
      @Override
      public Outcome assess(final SignatureInformation sigInfo) {

         final CertPathRevocationAnalysis certPathRevocationAnalysis = sigInfo.getCertPathRevocationAnalysis();
         final QualificationsVerification qualificationsVerification = sigInfo.getQualificationsVerification();
         final QCStatementInformation qcStatementInformation = sigInfo.getQcStatementInformation();

         final Outcome outcome = new Outcome();

         /*
          * although the code looks not nice, but for sake of clarity, we implement a distinct matrix exactly like the
          * one in FAD
          */
         final boolean serviceFound = certPathRevocationAnalysis.getTrustedListInformation().isServiceWasFound();
         int tlContentCase = -1;
         if (serviceFound) {

            tlContentCase = 0;
            if (qualificationsVerification != null) {

               if (qualificationsVerification.getQCWithSSCD().isValid()) {

                  tlContentCase = 1;
               }
               if (qualificationsVerification.getQCNoSSCD().isValid()) {

                  tlContentCase = 2;
               }
               if (qualificationsVerification.getQCSSCDStatusAsInCert().isValid()) {

                  tlContentCase = 3;
               }
               if (qualificationsVerification.getQCForLegalPerson().isValid()) {

                  tlContentCase = 4;
               }
            }
            if (!certPathRevocationAnalysis.getTrustedListInformation().isWellSigned()) {

               tlContentCase = 7;
               outcome.setComment("unsigned.tl.confirmation");
            }
         } else {

            // Case 5 and 6 are not discriminant */
            tlContentCase = 5;
            outcome.setComment("no.tl.confirmation");
         }

         int certContentCase = -1;
         if (qcStatementInformation != null) {

            boolean isOKQCC = qcStatementInformation.getQcCompliancePresent().isValid();
            boolean isOKQCP = qcStatementInformation.getQCPPresent().isValid();
            boolean isOKQCPP = qcStatementInformation.getQCPPlusPresent().isValid();
            boolean isOKQCSCCD = qcStatementInformation.getQcSCCDPresent().isValid();
            if (!isOKQCC && !isOKQCPP && isOKQCP && !isOKQCSCCD) {
               certContentCase = 0;
            }
            if (isOKQCC && !isOKQCPP && isOKQCP && !isOKQCSCCD) {
               certContentCase = 1;
            }
            if (isOKQCC && !isOKQCPP && isOKQCP && isOKQCSCCD) {
               certContentCase = 2;
            }
            if (!isOKQCC && isOKQCPP && !isOKQCP && !isOKQCSCCD) {
               certContentCase = 3;
            }
            if (isOKQCC && isOKQCPP && !isOKQCP && !isOKQCSCCD) {
               certContentCase = 4;
            }
            if (isOKQCC && isOKQCPP
            // QCPPlus stronger than QCP. If QCP is present, then it's ok.
            // && !isOKQCP
                     && isOKQCSCCD) {
               certContentCase = 5;
            }
            if (isOKQCC && !isOKQCPP && !isOKQCP && !isOKQCSCCD) {
               certContentCase = 6;
            }
            if (!isOKQCC && !isOKQCPP && !isOKQCP && isOKQCSCCD) {
               certContentCase = 7;
            }
            if (isOKQCC && !isOKQCPP && !isOKQCP && isOKQCSCCD) {
               certContentCase = 8;
            }
            if (!isOKQCC && !isOKQCPP && !isOKQCP && !isOKQCSCCD) {
               certContentCase = 9;
            }
         } else {

            certContentCase = 9;
         }
         LOG.info("[TLCase[" + (tlContentCase + 1) + "], CertCase [" + (certContentCase + 1) + "]]=" + MATRIX[tlContentCase][certContentCase]);

         try {
            outcome.setResult(MATRIX[tlContentCase][certContentCase]);
         } catch (IndexOutOfBoundsException ex) {
            outcome.setResult(FinalConclusion.UNDETERMINED);
         }

         return outcome;
      }
   }

   /**
    * The default constructor for SignatureInformation.
    * 
    * @param signatureVerification
    * @param certPathRevocationAnalysis
    * @param signatureLevelAnalysis
    * @param qualificationsVerification
    * @param qcStatementInformation
    */
   public SignatureInformation(SignatureVerification signatureVerification, CertPathRevocationAnalysis certPathRevocationAnalysis, SignatureLevelAnalysis signatureLevelAnalysis,
            QualificationsVerification qualificationsVerification, QCStatementInformation qcStatementInformation) {

      this.signatureVerification = signatureVerification;
      this.certPathRevocationAnalysis = certPathRevocationAnalysis;
      this.signatureLevelAnalysis = signatureLevelAnalysis;
      this.qualificationsVerification = qualificationsVerification;
      this.qcStatementInformation = qcStatementInformation;

      // note: this could become a class attribute to allow configuration
      // or (even better) to place this in another service
      final FinalConclusionStrategy finalConclusionStrategy = new DefaultFinalConclusionStrategy();
      final FinalConclusionStrategy.Outcome outcome = finalConclusionStrategy.assess(this);
      finalConclusionComment = (outcome == null) ? null : outcome.getComment();
      finalConclusion = (outcome == null) ? FinalConclusion.UNDETERMINED : outcome.getResult();
   }

   /**
    * @return the signatureVerification
    */
   public SignatureVerification getSignatureVerification() {
      return signatureVerification;
   }

   /**
    * @return the certPathRevocationAnalysis
    */
   public CertPathRevocationAnalysis getCertPathRevocationAnalysis() {
      return certPathRevocationAnalysis;
   }

   /**
    * @return the signatureLevelAnalysis
    */
   public SignatureLevelAnalysis getSignatureLevelAnalysis() {
      return signatureLevelAnalysis;
   }

   /**
    * @return the qualificationsVerification
    */
   public QualificationsVerification getQualificationsVerification() {
      return qualificationsVerification;
   }

   /**
    * @return the qcStatementInformation
    */
   public QCStatementInformation getQcStatementInformation() {
      return qcStatementInformation;
   }

   /**
    * @return the finalConclusion
    */
   public FinalConclusion getFinalConclusion() {
      return finalConclusion;
   }

   /**
    * @return the finalConclusionComment
    */
   public String getFinalConclusionComment() {
      return finalConclusionComment;
   }

   public String toString(String indentStr) {
      StringBuilder res = new StringBuilder();

      res.append(indentStr).append("[SignatureInformation\r\n");
      indentStr += "\t";

      if (getSignatureVerification() != null) {
         res.append(getSignatureVerification().toString(indentStr));
      }
      if (getCertPathRevocationAnalysis() != null) {
         res.append(getCertPathRevocationAnalysis().toString(indentStr));
      }
      if (getSignatureLevelAnalysis() != null) {
         res.append(getSignatureLevelAnalysis().toString(indentStr));
      }
      if (getQualificationsVerification() != null) {
         res.append(getQualificationsVerification().toString(indentStr));
      }
      if (getQcStatementInformation() != null) {
         res.append(getQcStatementInformation().toString(indentStr));
      }
      res.append("\r\n");
      res.append(indentStr).append("FinalConclusion: ").append(getFinalConclusion()).append("\r\n");
      res.append(indentStr).append("FinalConclusionComment: ").append(getFinalConclusionComment()).append("\r\n");

      indentStr = indentStr.substring(1);
      res.append(indentStr).append("]\r\n");

      return res.toString();
   }

   @Override
   public String toString() {
      return toString("");
   }

}
