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

package eu.europa.ec.markt.dss.ws;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Representation of a <i>SignedProperties</i> Element.
 * 
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (lun., 06 juin 2011) $
 */

public class SignedPropertiesContainer {

    private Date signingDate;

    private byte[] signingCertificate;

    private List<byte[]> certificateChain = new ArrayList<byte[]>();

    private String signaturePolicy;

    private String signaturePolicyId;

    private String signaturePolicyHashAlgo;

    private byte[] signaturePolicyHashValue;

    private String claimedSignerRole;

    private String signaturePackaging;

    /**
     * 
     * @return
     */
    public Date getSigningDate() {
        return signingDate;
    }

    /**
     * 
     * @param signingDate
     */
    public void setSigningDate(Date signingDate) {
        this.signingDate = signingDate;
    }

    /**
     * 
     * @return
     */
    public byte[] getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * 
     * @param signingCertificate
     */
    public void setSigningCertificate(byte[] signingCertificate) {
        this.signingCertificate = signingCertificate;
    }

    /**
     * 
     * @return
     */
    public List<byte[]> getCertificateChain() {
        return certificateChain;
    }

    /**
     * 
     * @param certificateChain
     */
    public void setCertificateChain(List<byte[]> certificateChain) {
        this.certificateChain = certificateChain;
    }

    /**
     * 
     * @return
     */
    public String getSignaturePolicy() {
        return signaturePolicy;
    }

    /**
     * 
     * @param signaturePolicy
     */
    public void setSignaturePolicy(String signaturePolicy) {
        this.signaturePolicy = signaturePolicy;
    }

    /**
     * 
     * @return
     */
    public String getSignaturePolicyId() {
        return signaturePolicyId;
    }

    /**
     * 
     * @param signaturePolicyId
     */
    public void setSignaturePolicyId(String signaturePolicyId) {
        this.signaturePolicyId = signaturePolicyId;
    }

    /**
     * 
     * @return
     */
    public String getSignaturePolicyHashAlgo() {
        return signaturePolicyHashAlgo;
    }

    /**
     * 
     * @param signaturePolicyHashAlgo
     */
    public void setSignaturePolicyHashAlgo(String signaturePolicyHashAlgo) {
        this.signaturePolicyHashAlgo = signaturePolicyHashAlgo;
    }

    /**
     * 
     * @return
     */
    public byte[] getSignaturePolicyHashValue() {
        return signaturePolicyHashValue;
    }

    /**
     * 
     * @param signaturePolicyHashValue
     */
    public void setSignaturePolicyHashValue(byte[] signaturePolicyHashValue) {
        this.signaturePolicyHashValue = signaturePolicyHashValue;
    }

    /**
     * 
     * @return
     */
    public String getClaimedSignerRole() {
        return claimedSignerRole;
    }

    /**
     * 
     * @param claimedSignerRole
     */
    public void setClaimedSignerRole(String claimedSignerRole) {
        this.claimedSignerRole = claimedSignerRole;
    }

    /**
     * 
     * @return
     */
    public String getSignaturePackaging() {
        return signaturePackaging;
    }

    /**
     * 
     * @param signaturePackaging
     */
    public void setSignaturePackaging(String signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
    }

}