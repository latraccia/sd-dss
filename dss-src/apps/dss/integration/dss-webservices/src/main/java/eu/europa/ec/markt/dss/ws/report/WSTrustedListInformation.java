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

import eu.europa.ec.markt.dss.validation.report.TrustedListInformation;

import java.util.Date;

/**
 * Contains trusted list information relevant to a certificate. Used to expose the information in the Webservice.
 * 
 * 
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSTrustedListInformation {

    private boolean serviceWasFound;

    private String tspName;

    private String tspTradeName;

    private String tspPostalAddress;

    private String tspElectronicAddress;

    private String serviceType;

    private String serviceName;

    private String currentStatus;

    private Date currentStatusStartingDate;

    private String statusAtReferenceTime;

    private Date statusStartingDateAtReferenceTime;

    /**
     * The default constructor for WSTrustedListInformation.
     */
    public WSTrustedListInformation() {
    }

    /**
     * The default constructor for WSTrustedListInformation.
     */
    public WSTrustedListInformation(TrustedListInformation info) {
        serviceWasFound = info.isServiceWasFound();
        tspName = info.getTSPName();
        tspTradeName = info.getTSPTradeName();
        tspPostalAddress = info.getTSPPostalAddress();
        tspElectronicAddress = info.getTSPElectronicAddress();
        serviceType = info.getServiceType();
        serviceName = info.getServiceName();
        currentStatus = info.getCurrentStatus();
        currentStatusStartingDate = info.getCurrentStatusStartingDate();
        statusAtReferenceTime = info.getStatusAtReferenceTime();
        statusStartingDateAtReferenceTime = info.getStatusStartingDateAtReferenceTime();
    }

    /**
     * @return the serviceWasFound
     */
    public boolean isServiceWasFound() {
        return serviceWasFound;
    }

    /**
     * @param serviceWasFound the serviceWasFound to set
     */
    public void setServiceWasFound(boolean serviceWasFound) {
        this.serviceWasFound = serviceWasFound;
    }

    /**
     * @return the tspName
     */
    public String getTspName() {
        return tspName;
    }

    /**
     * @param tspName the tspName to set
     */
    public void setTspName(String tspName) {
        this.tspName = tspName;
    }

    /**
     * @return the tspTradeName
     */
    public String getTspTradeName() {
        return tspTradeName;
    }

    /**
     * @param tspTradeName the tspTradeName to set
     */
    public void setTspTradeName(String tspTradeName) {
        this.tspTradeName = tspTradeName;
    }

    /**
     * @return the tspPostalAddress
     */
    public String getTspPostalAddress() {
        return tspPostalAddress;
    }

    /**
     * @param tspPostalAddress the tspPostalAddress to set
     */
    public void setTspPostalAddress(String tspPostalAddress) {
        this.tspPostalAddress = tspPostalAddress;
    }

    /**
     * @return the tspElectronicAddress
     */
    public String getTspElectronicAddress() {
        return tspElectronicAddress;
    }

    /**
     * @param tspElectronicAddress the tspElectronicAddress to set
     */
    public void setTspElectronicAddress(String tspElectronicAddress) {
        this.tspElectronicAddress = tspElectronicAddress;
    }

    /**
     * @return the serviceType
     */
    public String getServiceType() {
        return serviceType;
    }

    /**
     * @param serviceType the serviceType to set
     */
    public void setServiceType(String serviceType) {
        this.serviceType = serviceType;
    }

    /**
     * @return the serviceName
     */
    public String getServiceName() {
        return serviceName;
    }

    /**
     * @param serviceName the serviceName to set
     */
    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    /**
     * @return the currentStatus
     */
    public String getCurrentStatus() {
        return currentStatus;
    }

    /**
     * @param currentStatus the currentStatus to set
     */
    public void setCurrentStatus(String currentStatus) {
        this.currentStatus = currentStatus;
    }

    /**
     * @return the currentStatusStartingDate
     */
    public Date getCurrentStatusStartingDate() {
        return currentStatusStartingDate;
    }

    /**
     * @param currentStatusStartingDate the currentStatusStartingDate to set
     */
    public void setCurrentStatusStartingDate(Date currentStatusStartingDate) {
        this.currentStatusStartingDate = currentStatusStartingDate;
    }

    /**
     * @return the statusAtReferenceTime
     */
    public String getStatusAtReferenceTime() {
        return statusAtReferenceTime;
    }

    /**
     * @param statusAtReferenceTime the statusAtReferenceTime to set
     */
    public void setStatusAtReferenceTime(String statusAtReferenceTime) {
        this.statusAtReferenceTime = statusAtReferenceTime;
    }

    /**
     * @return the statusStartingDateAtReferenceTime
     */
    public Date getStatusStartingDateAtReferenceTime() {
        return statusStartingDateAtReferenceTime;
    }

    /**
     * @param statusStartingDateAtReferenceTime the statusStartingDateAtReferenceTime to set
     */
    public void setStatusStartingDateAtReferenceTime(Date statusStartingDateAtReferenceTime) {
        this.statusStartingDateAtReferenceTime = statusStartingDateAtReferenceTime;
    }

}
