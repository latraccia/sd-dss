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
package eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * In memory representation on the XML Validation Policy Constraint document
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
@XmlAccessorType(XmlAccessType.NONE)
@XmlRootElement(name = "ConstraintsParameters")
public class ValidationPolicy {

    @XmlAttribute(name = "Name", required = false)
    private String name;

    @XmlElement(name = "Description", required = false)
    private String description;

    @XmlElement(name = "RevocationFreshness", required = false)
    private DurationValue revocationFreshness;

    @XmlElement(name = "TimestampDelay", required = false)
    private DurationValue timestampDelay;

    @XmlElement(name = "AcceptablePolicies", required = false)
    private AcceptablePolicies acceptablePolicies;

    @XmlElement(name = "Cryptographic", required = false)
    private Cryptographic cryptographic;

    @XmlElement(name = "SigningCertificateChain", required = false)
    @NonVisual
    private SigningCertificateChain signingCertificateChain;

    @XmlElement(name = "MandatedSignedQProperties", required = false)
    private MandatedSignedQProperties mandatedSignedQProperties;

    @XmlElement(name = "MandatedUnsignedQProperties", required = false)
    private MandatedUnsignedQProperties mandatedUnsignedQProperties;

    @XmlElement(name = "OnRoles", required = false)
    @NonVisual
    private OnRoles onRoles;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public DurationValue getRevocationFreshness() {
        return revocationFreshness;
    }

    public void setRevocationFreshness(DurationValue revocationFreshness) {
        this.revocationFreshness = revocationFreshness;
    }

    public DurationValue getTimestampDelay() {
        return timestampDelay;
    }

    public void setTimestampDelay(DurationValue timestampDelay) {
        this.timestampDelay = timestampDelay;
    }

    public AcceptablePolicies getAcceptablePolicies() {
        return acceptablePolicies;
    }

    public void setAcceptablePolicies(AcceptablePolicies acceptablePolicies) {
        this.acceptablePolicies = acceptablePolicies;
    }

    public Cryptographic getCryptographic() {
        return cryptographic;
    }

    public void setCryptographic(Cryptographic cryptographic) {
        this.cryptographic = cryptographic;
    }

    public OnRoles getOnRoles() {
        return onRoles;
    }

    public void setOnRoles(OnRoles onRoles) {
        this.onRoles = onRoles;
    }

    public MandatedUnsignedQProperties getMandatedUnsignedQProperties() {
        return mandatedUnsignedQProperties;
    }

    public void setMandatedUnsignedQProperties(MandatedUnsignedQProperties mandatedUnsignedQProperties) {
        this.mandatedUnsignedQProperties = mandatedUnsignedQProperties;
    }

    public MandatedSignedQProperties getMandatedSignedQProperties() {
        return mandatedSignedQProperties;
    }

    public void setMandatedSignedQProperties(MandatedSignedQProperties mandatedSignedQProperties) {
        this.mandatedSignedQProperties = mandatedSignedQProperties;
    }

    public SigningCertificateChain getSigningCertificateChain() {
        return signingCertificateChain;
    }

    public void setSigningCertificateChain(SigningCertificateChain signingCertificateChain) {
        this.signingCertificateChain = signingCertificateChain;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String toString() {
        return "ValidationPolicy{" +
              "acceptablePolicies=" + acceptablePolicies +
              ", name='" + name + '\'' +
              ", description='" + description + '\'' +
              ", revocationFreshness=" + revocationFreshness +
              ", timestampDelay=" + timestampDelay +
              ", cryptographic=" + cryptographic +
              ", signingCertificateChain=" + signingCertificateChain +
              ", mandatedSignedQProperties=" + mandatedSignedQProperties +
              ", mandatedUnsignedQProperties=" + mandatedUnsignedQProperties +
              ", onRoles=" + onRoles +
              '}';
    }
}
