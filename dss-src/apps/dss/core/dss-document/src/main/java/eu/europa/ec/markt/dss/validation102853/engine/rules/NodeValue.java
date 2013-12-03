/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.validation102853.engine.rules;

public interface NodeValue {

    public static final String OK = "OK";
    public static final String KO = "NOT OK";
    public static final String NO_VALID_TIMESTAMP_LABEL = "There is no valid timestamp.";
    public static final String NO_TIMESTAMP_LABEL = "There is no timestamp.";

    public static final String XCV_SOCIS_LABEL = "The signature of the certificate is spoiled.";
    public static final String XCV_INNFCCII_LABEL = "The interval [notBefore, notAfter] for the certificate chain is inconsistent.";

    public static final String BBB_ICS_ISCI_LABEL = "Is the signer's certificate identified?";
    public static final String BBB_ICS_ICDVV_LABEL = "Is certificate's digest value valid?";
    public static final String BBB_ICS_IIASNE_LABEL = "Is the issuer and the serial number equal?";
    public static final String BBB_ICS_INFO_IIASNE_LABEL = "The issuer or the serial number are not equal.";
    public static final String BBB_VCI_IPK_LABEL = "Is the policy known?";
    public static final String BBB_XCV_ICTIVRSC_LABEL = "Is the current time in the validity range of the signer's certificate?";
    public static final String BBB_XCV_CTINIVRSC_LABEL = "The current time is not in the validity range of the signer's certificate.";
    public static final String BBB_XCV_CCINT_LABEL = "The certificate chain is not trusted.";
    public static final String BBB_XCV_CCCBB_LABEL = "Can the certificate chain be built?";
    public static final String BBB_XCV_IRDPFC_LABEL = "Is revocation data present for the certificate [%s]?";
    public static final String BBB_XCV_NRDFC_LABEL = "No revocation data for the certificate [%s]";
    public static final String BBB_XCV_IRIF_LABEL = "Is revocation information fresh for the certificate [%s]?";
    public static final String BBB_XCV_TVA_LABEL = "Try the validation again as of: %s";
    public static final String BBB_XCV_RIT_LABEL = "The revocation issuing time: %s";
    public static final String BBB_XCV_MAORD_LABEL = "The maximum age of the revocation data: %s";
    public static final String BBB_XCV_ISCR_LABEL = "Is the signer's certificate revoked?";
    public static final String BBB_XCV_ISCOH_LABEL = "Is the signer's certificate on hold?";
    public static final String BBB_XCV_ST_LABEL = "The suspension time: %s";
    public static final String BBB_XCV_IICR_LABEL = "Is an intermediate CA [%s] revoked?";
    public static final String BBB_XCV_ARDCCM_LABEL = "Are revocation data cryptographic constraints met?";
    public static final String BBB_XCV_ACCM_LABEL = "Are the chain constraints met?";
    public static final String BBB_XCV_CMDCIQC_LABEL = "Certificate meta-data constraints: Is the signer's certificate qualified?";
    public static final String BBB_XCV_SCINQ_LABEL = "The signer's certificate is not qualified.";
    public static final String BBB_XCV_CMDCISSCD_LABEL = "Certificate meta-data constraints: Is the SSCD?";
    public static final String BBB_XCV_ACCCM_LABEL = "Are the chain cryptographic constraints met?";
    public static final String BBB_XCV_CMDCIITLP_LABEL = "Certificate meta-data constraints: Is issued to a legal person?";
    public static final String BBB_CV_IRDOF_LABEL = "Is the reference data object(s) found?";
    public static final String BBB_CV_IRDOI_LABEL = "Is the reference data object(s) intact?";
    public static final String BBB_CV_ISI_LABEL = "Is the signature intact?";
    public static final String BBB_SAV_ISQPSTP_LABEL = "Is signed qualifying properties: 'signing-time' present?";
    public static final String BBB_SAV_ISQPSTP_ANS_LABEL = "The signed qualifying properties: 'signing-time' is not present";
    public static final String BBB_SAV_ISQPXTIP_LABEL = "Is signed qualifying properties: 'commitment-type-indication' present?";
    public static final String BBB_SAV_ISQPSLP_LABEL = "Is signed qualifying properties: 'signer-location' present?";
    public static final String BBB_SAV_IRM_LABEL = "Is the role mandated?";
    public static final String BBB_SAV_ASCCM_LABEL = "Are the signature cryptographic constraints met?";

    public static final String TSV_IRTPTBST_LABEL = "Is revocation time posterior to best-signature-time?";
    public static final String TSV_IBSTAIDOSC_LABEL = "The signature-time-stamp protects the signature against the revocation of the signer's certificate but not against expiration!";
    public static final String TSV_WACRABST_LABEL = "Were the algorithm(s) considered reliable at best-signature-time?";
    public static final String TSV_ASTPTCT_LABEL = "Are the signature timestamps posterior to the content timestamps?";
    public static final String TSV_ISTPAP_LABEL = "Is signing-time property/attribute present?";
    public static final String TSV_ISTPTDABST_LABEL = "Is the signing-time plus the timestamp delay after the best-signature-time?";

    public static final String ADEST_BSTIAIDSC_LABEL = "The best-signature-time is after the issuance date of the signer's certificate.";
    public static final String ADEST_ROBVPIIC_LABEL = "The result of the Basic Validation Process is it conclusive?";
    public static final String ADEST_ROVPFTIIC_LABEL = "The result of the Validation Process for timestamps is it conclusive?";
    public static final String ADEST_IMIVC_LABEL = "Is message imprint verification conclusive?";
    public static final String ADEST_ITVPC_LABEL = "Is timestamp validation process conclusive?";
    public static final String ADEST_TVINCBIGT_LABEL = "The timestamp %s is rejected, its generation time is before best-signature-time.";
    public static final String ADEST_TVINC_LABEL = "Timestamp %s validation is not conclusive.";
    public static final String ADEST_VFDTAOCST_LABEL = "The validation failed due to the absence of claimed signing time.";
    public static final String ADEST_VFDTTDC_LABEL = "The validation failed due to the timestamp delay constraint.";

    public static final String PSV_IPCVC_LABEL = "Is past certificate validation conclusive?";
    public static final String PSV_ITPOSVAOBCT_LABEL = "Is there a POE of the signature value at (or before) control-time?";
    public static final String PSV_IATVC_LABEL = "Is AdES-T validation conclusive?";
    public static final String PSV_IPSVC_LABEL = "Is past signature validation conclusive?";

    public static final String PCV_ICTSC_LABEL = "Is control time sliding conclusive?";
    public static final String PCV_TINTA_LABEL = "There is no trusted anchor.";
    public static final String PCV_TIOOCIC_LABEL = "There is only one certificate in the chain.";
    public static final String XCV_IFCCIIPC_LABEL = "The interval ['%s', '%s'] for the certificate ['%s'] is inconsistent in the prospective chain.";

    public static final String CTS_RBCTSSP_LABEL = "Returned by control time sliding sub-process.";
    public static final String CTS_WITSS_LABEL = "What is the trusted service status?";
    public static final String CTS_DRIE_LABEL = "Does the revocation information exist?";
    public static final String CTS_ICNEAIDORSI_LABEL = "Is the certificate not expired at the issuance date of the revocation status information?";
    public static final String CTS_IIDORSIBCT_LABEL = "Is the issuance date of the revocation status information before control-time?";
    public static final String CTS_DSOPCPOEOC_LABEL = "Does the set of POEs contains a proof of existence of the certificate?";
    public static final String CTS_SCT_LABEL = "Sliding the control-time.";
    public static final String CTS_CTSTRT_LABEL = "Control-time set to revocation time.";
    public static final String CTS_CTSTRIT_LABEL = "Control-time set to revocation issuing time.";
    public static final String CTS_RSIINCF_LABEL = "Revocation status information is not considered 'fresh'.";
    public static final String CTS_CTSTETOCSA_LABEL = "Control-time set to expiration time of the certificate's signature algorithm.";
    public static final String CTS_CTSTETORSA_LABEL = "Control-time set to expiration time of the revocation's signature algorithm.";

    // public static final String _LABEL = "";
    // public static final String _LABEL = "";
    // public static final String _LABEL = "";
    // public static final String _LABEL = "";
    // public static final String _LABEL = "";
    // public static final String _LABEL = "";
    // public static final String _LABEL = "";
    // public static final String _LABEL = "";
}
