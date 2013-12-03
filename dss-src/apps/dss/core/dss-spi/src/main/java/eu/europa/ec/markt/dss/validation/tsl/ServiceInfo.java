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

package eu.europa.ec.markt.dss.validation.tsl;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;

/**
 * From a validation point of view, a Service is a set of pair ("Qualification Statement", "Condition").
 * 
 * 
 * @version $Revision: 1776 $ - $Date: 2013-03-14 21:08:15 +0100 (jeu., 14 mars 2013) $
 */

public class ServiceInfo implements Serializable {

    private static final long serialVersionUID = 4903410679096343832L;

    private String type;

    private Map<String, Condition> qualifiersAndConditions = new HashMap<String, Condition>();

    private String tspName;

    private String tspTradeName;

    private String tspPostalAddress;

    private String tspElectronicAddress;

    private String serviceName;

    private String currentStatus;

    private Date currentStatusStartingDate;

    private String statusAtReferenceTime;

    private Date statusStartingDateAtReferenceTime;

    private Date statusEndingDateAtReferenceTime;

    private boolean tlWellSigned;

    /**
     * Add a qualifier and the corresponding condition
     * 
     * @param qualifier
     * @param condition
     */
    public void addQualifier(String qualifier, Condition condition) {
        qualifiersAndConditions.put(qualifier, condition);
    }

    /**
     * 
     * @return
     */
    public String getCurrentStatus() {
        return currentStatus;
    }

    /**
     * 
     * @return
     */
    public Date getCurrentStatusStartingDate() {
        return currentStatusStartingDate;
    }

    /**
     * Retrieve all the qualifiers for which the corresponding condition evaluate to true.
     * 
     * @param cert
     * @return
     */
    public List<String> getQualifiers(CertificateAndContext cert) {
        List<String> list = new ArrayList<String>();
        for (Entry<String, Condition> e : qualifiersAndConditions.entrySet()) {
            if (e.getValue().check(cert)) {
                list.add(e.getKey());
            }
        }
        return list;
    }

    /**
     * @return the qualifiersAndConditions
     */
    public Map<String, Condition> getQualifiersAndConditions() {
        return qualifiersAndConditions;
    }

    /**
     * 
     * @return
     */
    public String getServiceName() {
        return serviceName;
    }

    /**
     * 
     * @return
     */
    public String getStatusAtReferenceTime() {
        return statusAtReferenceTime;
    }

    /**
     * 
     * @return
     */
    public Date getStatusEndingDateAtReferenceTime() {
        return statusEndingDateAtReferenceTime;
    }

    /**
     * 
     * @return
     */
    public Date getStatusStartingDateAtReferenceTime() {
        return statusStartingDateAtReferenceTime;
    }

    /**
     * 
     * @return
     */
    public String getTspElectronicAddress() {
        return tspElectronicAddress;
    }

    /**
     * 
     * @return
     */
    public String getTspName() {
        return tspName;
    }

    /**
     * 
     * @return
     */
    public String getTspPostalAddress() {
        return tspPostalAddress;
    }

    /**
     * 
     * @return
     */
    public String getTspTradeName() {
        return tspTradeName;
    }

    /**
     * Return the type of the service
     * 
     * @return
     */
    public String getType() {
        return type;
    }

    /**
     * @return the tlWellSigned
     */
    public boolean isTlWellSigned() {
        return tlWellSigned;
    }

    /**
     * 
     * @param currentStatus
     */
    public void setCurrentStatus(String currentStatus) {
        this.currentStatus = currentStatus;
    }

    /**
     * 
     * @param currentStatusStartingDate
     */
    public void setCurrentStatusStartingDate(Date currentStatusStartingDate) {
        this.currentStatusStartingDate = currentStatusStartingDate;
    }

    /**
     * 
     * @param serviceName
     */
    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    /**
     * 
     * @param statusAtReferenceTime
     */
    public void setStatusAtReferenceTime(String statusAtReferenceTime) {
        this.statusAtReferenceTime = statusAtReferenceTime;
    }

    /**
     * 
     * @param statusEndingDateAtReferenceTime
     */
    public void setStatusEndingDateAtReferenceTime(Date statusEndingDateAtReferenceTime) {
        this.statusEndingDateAtReferenceTime = statusEndingDateAtReferenceTime;
    }

    /**
     * 
     * @param statusStartingDateAtReferenceTime
     */
    public void setStatusStartingDateAtReferenceTime(Date statusStartingDateAtReferenceTime) {
        this.statusStartingDateAtReferenceTime = statusStartingDateAtReferenceTime;
    }

    /**
     * @param tlWellSigned the tlWellSigned to set
     */
    public void setTlWellSigned(boolean tlWellSigned) {
        this.tlWellSigned = tlWellSigned;
    }

    /**
     * 
     * @param tspElectronicAddress
     */
    public void setTspElectronicAddress(String tspElectronicAddress) {
        this.tspElectronicAddress = tspElectronicAddress;
    }

    /**
     * 
     * @param tspName
     */
    public void setTspName(String tspName) {
        this.tspName = tspName;
    }

    /**
     * 
     * @param tspPostalAddress
     */
    public void setTspPostalAddress(String tspPostalAddress) {
        this.tspPostalAddress = tspPostalAddress;
    }

    /**
     * 
     * @param tspTradeName
     */
    public void setTspTradeName(String tspTradeName) {
        this.tspTradeName = tspTradeName;
    }

    /**
     * Define the type of the service
     * 
     * @param type
     */
    public void setType(String type) {
        this.type = type;
    }

    @Override
    public String toString() {

        StringBuffer buffer = new StringBuffer();
        buffer.append('\n').append("type=").append(type).append('\n');
        buffer.append("qualifiersAndConditions=").append(qualifiersAndConditions).append('\n');
        buffer.append("tspName=").append(tspName).append('\n');
        buffer.append("tspTradeName=").append(tspTradeName).append('\n');
        buffer.append("tspPostalAddress=").append(tspPostalAddress).append('\n');
        buffer.append("tspElectronicAddress=").append(tspElectronicAddress).append('\n');

        // private String serviceName;
        // private String currentStatus;
        // private Date currentStatusStartingDate;
        // private String statusAtReferenceTime;
        // private Date statusStartingDateAtReferenceTime;
        // private Date statusEndingDateAtReferenceTime;
        // private boolean tlWellSigned;
        return buffer.toString();
    }

}
