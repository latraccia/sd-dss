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

import eu.europa.ec.markt.dss.validation.tsl.Condition;
import eu.europa.ec.markt.dss.validation.tsl.QualificationElement;
import eu.europa.ec.markt.dss.validation.tsl.ServiceInfo;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Contains trusted list information relevant to a certificate
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class TrustedListInformation {
    @XmlElement
    private ServiceInfo trustService;

    public TrustedListInformation() {
    }

    /**
     * 
     * The default constructor for TrustedListInformation.
     * 
     * @param ts
     */
    public TrustedListInformation(ServiceInfo ts) {
        this.trustService = ts;
    }

    /**
     * @return the serviceWasFound
     */
    public boolean isServiceWasFound() {
        return trustService != null;
    }

    /**
     * 
     * @return
     */
    public String getTSPName() {
        if (trustService == null) {
            return null;
        }
        return trustService.getTspName();
    }

    /**
     * 
     * @return
     */
    public String getTSPTradeName() {
        if (trustService == null) {
            return null;
        }
        return trustService.getTspTradeName();
    }

    /**
     * 
     * @return
     */
    public String getTSPPostalAddress() {
        if (trustService == null) {
            return null;
        }
        return trustService.getTspPostalAddress();
    }

    /**
     * 
     * @return
     */
    public String getTSPElectronicAddress() {
        if (trustService == null) {
            return null;
        }
        return trustService.getTspElectronicAddress();
    }

    /**
     * 
     * @return
     */
    public String getServiceType() {
        if (trustService == null) {
            return null;
        }
        return trustService.getType();
    }

    /**
     * 
     * @return
     */
    public String getServiceName() {
        if (trustService == null) {
            return null;
        }
        return trustService.getServiceName();
    }

    /**
     * 
     * @return
     */
    public String getCurrentStatus() {
        if (trustService == null) {
            return null;
        }
        String status = trustService.getCurrentStatus();
        int slashIndex = status.lastIndexOf('/');
        if (slashIndex > 0 && slashIndex < status.length() - 1) {
            status = status.substring(slashIndex + 1);
        }
        return status;
    }

    /**
     * 
     * @return
     */
    public Date getCurrentStatusStartingDate() {
        if (trustService == null) {
            return null;
        }
        return trustService.getCurrentStatusStartingDate();
    }

    /**
     * 
     * @return
     */
    public String getStatusAtReferenceTime() {
        if (trustService == null) {
            return null;
        }
        String status = trustService.getStatusAtReferenceTime();
        int slashIndex = status.lastIndexOf('/');
        if (slashIndex > 0 && slashIndex < status.length() - 1) {
            status = status.substring(slashIndex + 1);
        }
        return status;
    }

    /**
     * 
     */
    public Date getStatusStartingDateAtReferenceTime() {
        if (trustService == null) {
            return null;
        }
        return trustService.getStatusStartingDateAtReferenceTime();
    }

    /**
     * Is the Trusted List well signed
     * 
     * @return
     */
    public boolean isWellSigned() {
        if (trustService == null) {
            return false;
        }
        return trustService.isTlWellSigned();
    }

    /**
     * Return the list of condition associated to this service<br>
     * --> use getQualificationElements() method.
     * 
     * @return
     */
    @Deprecated
    public List<QualificationElement> getQualitificationElements() {

        return getQualificationElements();
    }

    /**
     * Return the list of condition associated to this service
     * 
     * @return
     */
    public List<QualificationElement> getQualificationElements() {
        if (trustService == null) {
            return null;
        }
        List<QualificationElement> elements = new ArrayList<QualificationElement>();
        for (Entry<String, Condition> e : trustService.getQualifiersAndConditions().entrySet()) {
            elements.add(new QualificationElement(e.getKey(), e.getValue()));
        }
        return elements;
    }

}
