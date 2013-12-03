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

public interface AttributeValue {

    public static final String BBB_ICS_ISCI = "BBB_ICS_ISCI";
    public static final String BBB_ICS_ICDVV = "BBB_ICS_ICDVV";
    public static final String BBB_ICS_IIASNE = "BBB_ICS_IIASNE";
    public static final String BBB_VCI_IPK = "BBB_VCI_IPK";
    public static final String BBB_XCV_CCCBB = "BBB_XCV_CCCBB";
    public static final String BBB_XCV_IRIF = "BBB_XCV_IRIF";
    public static final String BBB_XCV_IRDPFC = "BBB_XCV_IRDPFC";
    public static final String BBB_XCV_ISCR = "BBB_XCV_ISCR";
    public static final String BBB_XCV_ISCOH = "BBB_XCV_ISCOH";
    public static final String BBB_XCV_IICR = "BBB_XCV_IICR";
    public static final String BBB_XCV_ARDCCM = "BBB_XCV_ARDCCM";
    public static final String BBB_XCV_CMDCIQC = "BBB_XCV_CMDCIQC";
    public static final String BBB_XCV_CMDCISSCD = "BBB_XCV_CMDCISSCD";
    public static final String BBB_XCV_ACCCM = "BBB_XCV_ACCCM";
    public static final String BBB_XCV_ACCM = "BBB_XCV_ACCM";
    public static final String BBB_XCV_ICTIVRSC = "BBB_XCV_ICTIVRSC";
    public static final String BBB_CV_IRDOI = "BBB_CV_IRDOI";
    public static final String BBB_CV_ISI = "BBB_CV_ISI";
    public static final String BBB_XCV_CMDCIITLP = "BBB_XCV_CMDCIITLP";
    public static final String BBB_CV_IRDOF = "BBB_CV_IRDOF";
    public static final String BBB_SAV_ISQPSTP = "BBB_SAV_ISQPSTP";
    public static final String BBB_SAV_ISQPXTIP = "BBB_SAV_ISQPXTIP";
    public static final String BBB_SAV_ISQPSLP = "BBB_SAV_ISQPSLP";
    public static final String BBB_SAV_IRM = "BBB_SAV_IRM";
    public static final String BBB_SAV_ASCCM = "BBB_SAV_ASCCM";

    public static final String TSV_IRTPTBST = "TSV_IRTPTBST";
    public static final String TSV_IBSTAIDOSC = "TSV_IBSTAIDOSC";
    public static final String TSV_WACRABST = "TSV_WACRABST";
    public static final String TSV_ASTPTCT = "TSV_ASTPTCT";
    public static final String TSV_ISTPAP = "TSV_ISTPAP";
    public static final String TSV_ISTPTDABST = "TSV_ISTPTDABST";

    public static final String ADEST_ROBVPIIC = "ADEST_ROBVPIIC";
    public static final String ADEST_ROVPFTIIC = "ADEST_ROVPFTIIC";
    public static final String ADEST_IMIVC = "ADEST_IMIVC";
    public static final String ADEST_ITVPC = "ADEST_ITVPC";

    public static final String PSV_IPCVC = "PSV_IPCVC";
    public static final String PSV_ITPOSVAOBCT = "PSV_ITPOSVAOBCT";
    public static final String PSV_IATVS = "PSV_IATVS";
    public static final String PSV_IPSVC = "PSV_IPSVC";

    public static final String PCV_ICTSC = "PCV_ICTSC";

    public static final String CTS_ITSUS = "CTS_ITSUS";
    public static final String CTS_DRIE = "CTS_DRIE";
    public static final String CTS_ICNEAIDORSI = "CTS_ICNEAIDORSI";
    public static final String CTS_IIDORSIBCT = "CTS_IIDORSIBCT";
    public static final String CTS_DSOPCPOEOC = "CTS_DSOPCPOEOC";
    public static final String CTS_SCT = "CTS_SCT";

    public static final String NOT_BEFORE = "NotBefore";
    public static final String NOT_AFTER = "NotAfter";
    public static final String EXPIRED_CERTS_REVOCATION_INFO = "expiredCertsRevocationInfo";
    public static final String REVOCATION = "Revocation";
    public static final String REVOCATION_ISSUING_TIME = "RevocationIssuingTime";
    public static final String REVOCATION_TIME = "RevocationTime";
    public static final String REVOCATION_REASON = "RevocationReason";
    public static final String CERT_ID = "CertId";
    public static final String CERTIFICATE = "Certificate";
    public static final String BEST_SIGNATURE_TIME = "BestSignatureTime";
    public static final String CONTROL_TIME = "ControlTime";
    public static final String ALGORITHM_NOT_FOUND = "Algorithm not found";
    public static final String TRUSTED_SERVICE_STATUS = "TrustedServiceStatus";
    public static final String TIMESTAMP_PRODUCTION_TIME = "TimestampProductionTime";
    public static final String SIGNATURE_ID = "SignatureId";

    public static final String ALGO_EXPIRATION_DATE = "AlgoExpirationDate";

    // public static final String = "";
    // public static final String = "";
    // public static final String = "";
    // public static final String = "";
    // public static final String = "";
    // public static final String = "";
    // public static final String = "";
    // public static final String = "";
    // public static final String = "";
}
