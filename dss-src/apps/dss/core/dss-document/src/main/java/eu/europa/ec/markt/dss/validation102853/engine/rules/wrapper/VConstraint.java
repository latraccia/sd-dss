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

package eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleConstant;
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleUtils;

/**
 * This class encapsulates the constraint file that controls the policy to be used during the validation process. It
 * adds the functions to direct access to the file data.
 *
 * @author bielecro
 */
public class VConstraint extends XmlDom implements RuleConstant {

    private long maxRevocationFreshnessString;

    private String maxRevocationFreshnessUnit;

    private Long maxRevocationFreshness;

    private Long timestampDelayTime;

    private Map<String, Date> algoExpirationDate = new HashMap<String, Date>();

    private List<String> knownPolicies;

    public VConstraint(Document document) {

        super(document);
    }

    /**
     * @return
     */
    public boolean isRevocationFreshnessToBeChecked() {

        return null != getElement("/ConstraintsParameters/RevocationFreshness/");
    }

    public String getFormatedMaxRevocationFreshness() {

        if (maxRevocationFreshness == null) {

            getMaxRevocationFreshness();
        }
        return maxRevocationFreshnessString + " " + maxRevocationFreshnessUnit;
    }

    /**
     * This function returns the maximum duration in milliseconds for which the revocation data are considered fresh.
     *
     * @return
     */
    public Long getMaxRevocationFreshness() {

        if (maxRevocationFreshness == null) {

            maxRevocationFreshness = Long.MAX_VALUE;

            final XmlDom revocationFreshness = getElement("/ConstraintsParameters/RevocationFreshness");
            if (revocationFreshness != null) {

                maxRevocationFreshnessString = getLongValue("/ConstraintsParameters/RevocationFreshness/text()");
                maxRevocationFreshnessUnit = getValue("/ConstraintsParameters/RevocationFreshness/@Unit");
                maxRevocationFreshness = RuleUtils.convertDuration(maxRevocationFreshnessUnit, "MILLISECONDS", maxRevocationFreshnessString);
                if (maxRevocationFreshness == 0) {

                    maxRevocationFreshness = Long.MAX_VALUE;
                }
            }
        }
        return maxRevocationFreshness;
    }

    /**
     * This function returns the algorithm expiration date extracted from the 'constraint.xml' file. If the TAG AlgoExpirationDate is not present within the
     * constraints {@code null} is returned.
     *
     * @param algo algorithm (SHA1, SHA256, RSA2048...) to be checked
     * @return expiration date or null
     */
    public Date getAlgorithmExpirationDate(final String algo) {

        Date date = algoExpirationDate.get(algo);
        if (date == null) {

            final XmlDom algoExpirationDateDom = getElement("/ConstraintsParameters/Cryptographic/AlgoExpirationDate");
            if (algoExpirationDateDom == null) {

                return null;
            }
            String expirationDateFormat = algoExpirationDateDom.getValue("./@Format");
            if (expirationDateFormat.isEmpty()) {

                expirationDateFormat = "yyyy-MM-dd";
            }

            final String expirationDateString = algoExpirationDateDom.getValue("./Algo[@Name='%s']/text()", algo);
            if (expirationDateString.isEmpty()) {

                throw new DSSException(String.format("The the expiration date is not defined for '%s' algorithm!", algo));
            }
            date = RuleUtils.parseDate(expirationDateFormat, expirationDateString);
            algoExpirationDate.put(algo, date);
        }
        return date;
    }

    /**
     * Indicates if the encryption algorithm is acceptable.
     *
     * @param contextName
     * @param algo
     * @return
     */
    public boolean isAcceptableEncryptionAlgo(final String contextName, final String algo) {

        final boolean found = exists("/ConstraintsParameters/Cryptographic/%s/AcceptableEncryptionAlgo[dss:Algo='%s']/Algo", contextName, algo);
        return found;
    }

    /**
     * Indicates if the digest algorithm is acceptable.
     *
     * @param contextName
     * @param algo
     * @return
     */
    public boolean isAcceptableDigestAlgo(final String contextName, final String algo) {

        final boolean found = exists("/ConstraintsParameters/Cryptographic/%s/AcceptableDigestAlgo[dss:Algo='%s']/Algo", contextName, algo);
        return found;
    }

    /**
     * Indicates if the encryption algorithm minimum public key size.
     *
     * @param contextName
     * @param algo
     * @return -1 is returned if the value is not found or faulty.
     */
    public long getMiniPublicKeySize(final String contextName, final String algo) {

        long pkSize = -1;
        try {

            pkSize = getLongValue("/ConstraintsParameters/Cryptographic/%s/MiniPublicKeySize/Size[@Algo='%s']/text()", contextName, algo);
        } catch (Exception e) {
            // pkSize set to -1
        }
        return pkSize;
    }

    /**
     * Indicates if the presence of the signing time is mandatory.
     *
     * @return
     */
    public boolean shouldCheckIfSigningTimeIsPresent() {

        final boolean checkIfSigningTimeIsPresent = getBoolValue("/ConstraintsParameters/MandatedSignedQProperties/SigningTime/text()");
        return checkIfSigningTimeIsPresent;
    }

    /**
     * Indicates if the presence of the Commitment Type Indication is mandatory.
     *
     * @return
     */
    public boolean shouldCheckIfCommitmentTypeIndicationIsPresent() {

        final boolean checkIfCommitmentTypeIndicationIsPresent = getBoolValue(
              "/ConstraintsParameters/MandatedSignedQProperties/CommitmentTypeIndication/text()");
        return checkIfCommitmentTypeIndicationIsPresent;
    }

    /**
     * Indicates if the presence of the Signer Location is mandatory.
     *
     * @return
     */
    public boolean shouldCheckIfSignerLocationIsPresent() {

        final boolean checkIfSignerLocationIsPresent = getBoolValue("/ConstraintsParameters/MandatedSignedQProperties/SignerLocation/text()");
        return checkIfSignerLocationIsPresent;
    }

    /**
     * Indicates if the presence of the Signer Role is mandatory.
     *
     * @return
     */
    public boolean shouldCheckIfSignerRoleIsPresent() {

        final boolean checkIfSignerRoleIsPresent = getBoolValue("/ConstraintsParameters/OnRoles/RoleMandated/text()");
        return checkIfSignerRoleIsPresent;
    }

    /**
     * Return the mandated signer role.
     *
     * @return
     */
    public String getRequestedSignerRole() {

        final String requestedSignerRole = getValue("/ConstraintsParameters/OnRoles/RoleValue/text()");
        return requestedSignerRole;
    }

    /**
     * Indicates if the signing certificate must be qualified.
     *
     * @param context
     * @return
     */
    public boolean mustBeQualifiedCertificate(final String context) {

        final boolean mustBe = getBoolValue("/ConstraintsParameters/%s/QualifiedCertificate/text()", context);
        return mustBe;
    }

    /**
     * Indicates if the end user certificate used in validating the signature is mandated to be supported by a secure
     * signature creation device (SSCD) as defined in Directive 1999/93/EC [9].
     *
     * @param context
     * @return
     */
    public boolean mustBeSSCDCertificate(final String context) {

        final boolean mustBe = getBoolValue("/ConstraintsParameters/%s/SSCD/text()", context);
        return mustBe;
    }

    /**
     * Indicates if the signer's certificate used in validating the signature is mandated to be issued by a certificate
     * authority issuing certificate as having been issued to a legal person.
     *
     * @param context
     * @return
     */
    public boolean mustBeForLegalPersonCertificate(final String context) {

        final boolean mustBe = getBoolValue("/ConstraintsParameters/%s/ForLegalPerson/text()", context);
        return mustBe;
    }

    /**
     * Returns the name of the policy.
     *
     * @return
     */
    public String getPolicyName() {

        final String policy = getValue("/ConstraintsParameters/@Name");
        return policy;
    }

    /**
     * Returns the policy description.
     *
     * @return
     */
    public String getPolicyDescription() {

        final String description = getValue("/ConstraintsParameters/Description/text()");
        return description;
    }

    /**
     * Indicates if any policy is acceptable.
     *
     * @return
     */
    public boolean isAnyPolicyAcceptable() {

        return isPolicyAcceptable(ANY_POLICY);
    }

    /**
     * Indicates if the given policy is acceptable.
     *
     * @param policyId
     * @return
     */
    public boolean isPolicyAcceptable(final String policyId) {

        if (knownPolicies == null) {

            List<XmlDom> domList = getElements("/ConstraintsParameters/AcceptablePolicies/Id");
            knownPolicies = convertToStringList(domList);
        }
        final boolean found = knownPolicies.contains(policyId);
        return found;
    }

    /**
     * Returns the timestamp delay in milliseconds.
     *
     * @return
     */
    public Long getTimestampDelayTime() {

        if (timestampDelayTime == null) {

            final XmlDom timestampDelayPresent = getElement("/ConstraintsParameters/TimestampDelay");
            if (timestampDelayPresent == null) {

                return null;
            }
            final long timestampDelay = getLongValue("/ConstraintsParameters/TimestampDelay/text()");
            final String timestampUnit = getValue("/ConstraintsParameters/TimestampDelay/@Unit");
            timestampDelayTime = RuleUtils.convertDuration(timestampUnit, "MILLISECONDS", timestampDelay);
        }
        return timestampDelayTime;
    }
}
