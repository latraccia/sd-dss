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

package eu.europa.ec.markt.tlmanager.core.validation;

import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

import org.apache.commons.lang.StringUtils;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.core.Configuration.CountryCodes;
import eu.europa.ec.markt.tlmanager.core.QNames;
import eu.europa.ec.markt.tlmanager.core.validation.StatusInformationFlow.Status;
import eu.europa.ec.markt.tlmanager.util.Util;
import eu.europa.ec.markt.tsl.jaxb.ecc.CriteriaListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageBitType;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageType;
import eu.europa.ec.markt.tsl.jaxb.ecc.PoliciesListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationElementType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationsType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifierType;
import eu.europa.ec.markt.tsl.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.AnyType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ElectronicAddressType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionsListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.InternationalNamesType;
import eu.europa.ec.markt.tsl.jaxb.tsl.MultiLangNormStringType;
import eu.europa.ec.markt.tsl.jaxb.tsl.MultiLangStringType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NextUpdateType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyURIListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.OtherTSLPointerType;
import eu.europa.ec.markt.tsl.jaxb.tsl.PostalAddressType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceHistoryType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServiceInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServiceType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServicesListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustStatusListType;
import eu.europa.ec.markt.tsl.jaxb.tslx.CertSubjectDNAttributeType;
import eu.europa.ec.markt.tsl.jaxb.tslx.ExtendedKeyUsageType;
import eu.europa.ec.markt.tsl.jaxb.tslx.TakenOverByType;
import eu.europa.ec.markt.tsl.jaxb.xades.IdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectIdentifierType;

/**
 * Validation of a <code>TrustStatusListType</code>.
 * First all relevant jaxb-object-hierarchy segments are extracted an checked in two phases:<p>
 * 1. checking of mandatory values ('checkMandatory'...)
 * 2. checking of business rules ('checkRule'...)<p>
 * If there are errors in phase 1, the 2nd phase won't be started. Although the individual validation
 * methods here may rely on the work of <code>ObjectFiller</code>, null checks are done again extensively.
 * 
 *
 * @version $Revision: 2840 $ - $Date: 2013-11-04 12:30:49 +0100 (lun., 04 nov. 2013) $
 */
@SuppressWarnings("unused")
public class Validation {
    private static final Logger LOG = Logger.getLogger(Validation.class.getName());

    private enum TYPEFORMATS {
        NUMBER, TEXT, DATE, URL
    };

    private TrustStatusListType tsl;
    private ValidationParameters vParams;
    private static final ResourceBundle uiKeys = ResourceBundle.getBundle("eu/europa/ec/markt/tlmanager/uiKeysCore",
            Configuration.getInstance().getLocale());
    // exploded objects
    private TSLSchemeInformationType schemeInformation;
    private List<OtherTSLPointerType> pointers;
    private List<TSPType> tsps;
    private List<TSPServiceType> services;
    private List<ServiceHistoryInstanceType> histories;
    private List<ExtensionsListType> extensions;

    private ValidationLogger logger;

    private enum NODENAMES {
        Tsl, Pointer, Tsp, Service, History, Extension
    };

    /**
     * Instantiates a new validation.
     * 
     * @param tsl the tsl
     */
    public Validation(ValidationParameters vp, TrustStatusListType tsl) {
        this.tsl = tsl;
        this.vParams = vp;
        explodeTSL();
        logger = new ValidationLogger();
    }

    /**
     * Performs the validation.
     */
    public ValidationLogger validate() {
        // 1st phase
        callMethods("checkMandatory");
        // if there are errors till now, next phase is not started
        if (logger.hasErrors()) {
            logger.info(uiKeys.getString("Validation.mandatory.fieldsNOk"));
        } else {
            // 2nd phase
            logger.info(uiKeys.getString("Validation.mandatory.fieldsOk"));
            callMethods("checkRule");
            if (logger.hasErrors()) {
                logger.info(uiKeys.getString("Validation.mandatory.rulesNOk"));
            } else {
                logger.info(uiKeys.getString("Validation.mandatory.rulesOk"));
            }
        }

        return logger;
    }

    private void callMethods(String methodNamePrefix) {
        for (Method m : this.getClass().getDeclaredMethods()) {
            if (m.getName().startsWith(methodNamePrefix)) {
                try {
                    m.invoke(this, null);
                } catch (Exception ex) {
                    String name = m.getName();
                    LOG.log(Level.SEVERE, ">>> Cannot call the following method: " + name + " with " + ex.getMessage(),
                          ex);
                    logger.info(uiKeys.getString("Validation.mandatory.internalError") + " " + name);
                }
            }
        }
    }

    // Note: tsl and schemeInformation are the only objects that do not need to be null-checked
    private void explodeTSL() {
        schemeInformation = tsl.getSchemeInformation();

        if (schemeInformation.getPointersToOtherTSL() != null) {
            pointers = schemeInformation.getPointersToOtherTSL().getOtherTSLPointer();
        }

        if (tsl.getTrustServiceProviderList() != null) {
            tsps = tsl.getTrustServiceProviderList().getTrustServiceProvider();
        }

        if (tsps != null && !tsps.isEmpty()) {
            services = new ArrayList<TSPServiceType>();
            histories = new ArrayList<ServiceHistoryInstanceType>();
            extensions = new ArrayList<ExtensionsListType>();

            for (TSPType tsp : tsps) {
                if (tsp.getTSPServices() != null) {
                    services.addAll(tsp.getTSPServices().getTSPService());
                }
            }

            for (TSPServiceType service : services) {
                if (service.getServiceHistory() != null
                        && !service.getServiceHistory().getServiceHistoryInstance().isEmpty()) {
                    histories.addAll(service.getServiceHistory().getServiceHistoryInstance());
                }
                if (service.getServiceInformation() != null
                        && service.getServiceInformation().getServiceInformationExtensions() != null) {
                    extensions.add(service.getServiceInformation().getServiceInformationExtensions());
                }
            }

            // there may be more extensions
            for (ServiceHistoryInstanceType history : histories) {
                if (history.getServiceInformationExtensions() != null) {
                    extensions.add(history.getServiceInformationExtensions());
                }
            }
        }
    }

    private void validateSimple(NODENAMES name, String field, Object type, TYPEFORMATS typeFormat, Object parent) {
        boolean fieldIsEmpty = false;
        if (type == null) {
            fieldIsEmpty = true;
        } else if (type instanceof String && StringUtils.isBlank((String) type)) {
            fieldIsEmpty = true;
        } else if (typeFormat.equals(TYPEFORMATS.TEXT)) {
            String str = (String) type;
            if (str.isEmpty() || str.equals(Util.DEFAULT_NO_SELECTION_ENTRY)) {
                fieldIsEmpty = true;
            }
        } else if (typeFormat.equals(TYPEFORMATS.NUMBER)) {
            if (type instanceof BigInteger) {
                BigInteger big = (BigInteger) type;
                if (big.toString().isEmpty()) {
                    fieldIsEmpty = true;
                }
            }
        } else if (typeFormat.equals(TYPEFORMATS.URL)) {
            // nop
        } else if (typeFormat.equals(TYPEFORMATS.DATE)) {
            // nop
        }

        if (fieldIsEmpty) {
            logger.error(logger.getEmptyMessage(name.toString(), field), parent);
        }
    }

    private void validateList(NODENAMES name, String field, List<?> list, Object parent) {
        boolean isEmpty = false;
        String message = "";
        if (list == null || list.isEmpty()) {
            isEmpty = true;
        } else {
            for (Object item : list) {
                if (item instanceof MultiLangStringType) {
                    MultiLangStringType type = (MultiLangStringType) item;
                    if (type.getValue() == null || type.getValue().isEmpty()
                            || type.getValue().equals(Util.DEFAULT_NO_SELECTION_ENTRY)) {
                        isEmpty = true;
                    } else {
                        isEmpty = false;
                        break;
                    }
                } else if (item instanceof String) {
                    String type = (String) item;
                    if (type == null || type.isEmpty() || type.equals(Util.DEFAULT_NO_SELECTION_ENTRY)) {
                        isEmpty = true;
                    } else {
                        isEmpty = false;
                        break;
                    }
                } else if (item instanceof MultiLangNormStringType) {
                    MultiLangNormStringType type = (MultiLangNormStringType) item;
                    if (type.getValue() == null || type.getValue().isEmpty()) {
                        isEmpty = true;
                    } else {
                        isEmpty = false;
                        break;
                    }
                } else if (item instanceof PostalAddressType) {
                    PostalAddressType type = (PostalAddressType) item;
                    message = logger.getPrefix(name.toString(), field)
                            + uiKeys.getString("Validation.mandatory.postalAddress.minimumFields");
                    if (type.getStreetAddress() == null || type.getStreetAddress().isEmpty()) {
                        isEmpty = true;
                    } else if (type.getLocality() == null || type.getLocality().isEmpty()) {
                        isEmpty = true;
                    } else if (type.getCountryName() == null
                            || type.getCountryName().equals(Util.DEFAULT_NO_SELECTION_ENTRY)) {
                        isEmpty = true;
                    } else {
                        isEmpty = false;
                        break;
                    }
                } else if (item instanceof NonEmptyMultiLangURIType) {
                    NonEmptyMultiLangURIType type = (NonEmptyMultiLangURIType) item;
                    if (type.getValue() == null || type.getValue().isEmpty()) {
                        isEmpty = true;
                    } else {
                        isEmpty = false;
                        break;
                    }
                } else if (item instanceof PoliciesListType) {
                    PoliciesListType type = (PoliciesListType) item;
                    if (type.getPolicyIdentifier() == null || type.getPolicyIdentifier().isEmpty()) {
                        isEmpty = true;
                    } else {
                        boolean foundOneId = false;
                        for (ObjectIdentifierType id: type.getPolicyIdentifier()) {
                            IdentifierType identifier = id.getIdentifier();
                            if (identifier != null && identifier.getValue() != null
                                    && !identifier.getValue().isEmpty()) {
                                foundOneId = true;
                                break;
                            }
                        }
                        if (!foundOneId) {
                            isEmpty = true;
                        }
                    }
                }
                // else {
                // System.out.println("please handle me: "+item.toString());
                // }
            }
        }

        if (isEmpty) {
            if (message.isEmpty()) {
                message = logger.getEmptyMessage(name.toString(), field);
            }
            logger.error(message, parent);
        }
    }

    /**
     * Validates a ServiceDigitalIdentities by comparing its values with its certificate (if any). 
     * Furthermore, there has to be a certificate for a service and either a certificate, ski or subject name
     * for a history.
     * 
     * @param name the name of the governing object node
     * @param type the type to check
     * @param parent the reference object
     * @param certNotMandatory if true, it is not mandatory to have a certificate, but at least a subject name or ski
     */
    private void validateSpecial(NODENAMES name, DigitalIdentityListType type, Object parent, boolean certNotMandatory) {
        boolean gotCert = false, gotSubName = false, gotSKI = false;
        String field = QNames._ServiceDigitalIdentities_QNAME.getLocalPart();
        if (type == null) {
            logger.error(logger.getEmptyMessage(name.toString(), field), parent);
            return;
        }
        
        X500Principal certSName = null, sName = null;
        byte[] certSki = null, ski = null;
        List<DigitalIdentityType> digitalIds = type.getDigitalId();
        // first check on all the data that is available
        for (DigitalIdentityType ids: digitalIds) {
            if (ids.getX509Certificate() != null) {
                try {
                    ByteArrayInputStream bais = new ByteArrayInputStream(ids.getX509Certificate());
                    X509Certificate certificate = DSSUtils.loadCertificate(bais);
                    gotCert = true;

                    certSName = certificate.getSubjectX500Principal();
                    certSki = DSSUtils.getSki(certificate);
                } catch (DSSException ce) {
                    String message = uiKeys.getString("Validation.mandatory.certificate.invalid" + " - " + ce.getMessage());
                    LOG.log(Level.SEVERE, message);
                    logger.error(message, parent);
                }
            } else if (ids.getX509SubjectName() != null) {
                gotSubName = true;
                sName = new X500Principal(ids.getX509SubjectName());
            } else if (ids.getX509SKI() != null) {
                gotSKI = true;
                ski = ids.getX509SKI();
            }
        }
        
        // check 'internal' inconsistencies
        if (sName != null && certSName != null && !sName.equals(certSName)) {
            logger.error(uiKeys.getString("Validation.mandatory.certificate.mismatch.subjectname"), parent);
        }

        if (ski != null && certSki != null) {
            byte[] shorterSki = ski;
            byte[] longerSki = certSki;
            if (ski.length != certSki.length) {
                if (ski.length > certSki.length) {
                    shorterSki = certSki;
                    longerSki = ski;
                }
                longerSki = Arrays.copyOfRange(longerSki, longerSki.length - shorterSki.length, longerSki.length);
            }
            if (!Arrays.equals(shorterSki, longerSki)) {
                logger.error(uiKeys.getString("Validation.mandatory.certificate.mismatch.ski"), parent);
            }
        }
        
        if (certNotMandatory) { // history
            if (!gotSubName && !gotSKI && !gotCert) {
                logger.error(logger.getEmptyMessage(name.toString(), field), parent);
            } else if (!gotSubName) {   // subjectname is recommended
                logger.warn(logger.getPrefix(name.toString(), field)
                      + uiKeys.getString("Validation.mandatory.certificate.noSubjectName"), parent);
            }
        } else {    // service
            if (!gotCert) {
                logger.error(logger.getEmptyMessage(name.toString(), field), parent);
            }
        }
    }

    private void validateSpecial(NODENAMES name, TakenOverByType type, Object parent) {
        String field = QNames._TakenOverBy_QNAME.getLocalPart();
        boolean uri = false, tspName = false, operName = false, territory = false, oneIsSet = false;
        if (type.getURI() != null && type.getURI().getValue() != null && !type.getURI().getValue().isEmpty()) {
            uri = true;
            oneIsSet = true;
        }
        if (type.getTSPName() != null && !type.getTSPName().getName().isEmpty()) {
            tspName = true;
            oneIsSet = true;
        }
        if (type.getSchemeOperatorName() != null && !type.getSchemeOperatorName().getName().isEmpty()) {
            operName = true;
            oneIsSet = true;
        }
        if (type.getSchemeTerritory() != null && !type.getSchemeTerritory().isEmpty()
                && !type.getSchemeTerritory().equals(Util.DEFAULT_NO_SELECTION_ENTRY)) {
            territory = true;
            oneIsSet = true;
        }

        // as soon as one value is set, the rest has to be present also
        if (oneIsSet && (!uri || !tspName || !operName || !territory)) {
            logger.error(
                    logger.getPrefix(name.toString(), field)
                            + uiKeys.getString("Validation.mandatory.takenOverBy.minimumFields"), parent);
        }
    }

    private void validateSpecial(NODENAMES name, AdditionalServiceInformationType type, Object parent) {
        String field = QNames._AdditionalServiceInformation_QNAME.getLocalPart();
        boolean info = false;
        if (type.getInformationValue() != null && !type.getInformationValue().isEmpty()) {
            info = true;
        }
        if (type.getURI() == null || type.getURI().getValue().isEmpty()
                || type.getURI().getValue().equals(Util.DEFAULT_NO_SELECTION_ENTRY)) {
            if (info) { // uri is the only mandatory field; if there is no info, the whole thing is empty
                logger.error(
                        logger.getPrefix(name.toString(), field)
                                + uiKeys.getString("Validation.mandatory.additionalServiceInformation.minimumFields"),
                        parent);
            }
        }
    }

    private void validateSpecial(NODENAMES name, QualificationsType type) {
        String field = QNames._Qualifications_QNAME.getLocalPart();
        if (type != null) {
            for (QualificationElementType element : type.getQualificationElement()) {
                // ecc:Qualifiers - 2 ecc:Qualifier
                boolean isEmpty = false;
                if (element.getQualifiers() == null || element.getQualifiers().getQualifier().isEmpty()) {
                    isEmpty = true;
                } else {
                    List<QualifierType> qualifiers = element.getQualifiers().getQualifier();
                    // if (qualifiers.size() >= 1) {
                    String uri1 = qualifiers.get(0).getUri();
                    if (uri1 == null || uri1.isEmpty() || uri1.equals(Util.DEFAULT_NO_SELECTION_ENTRY)) {
                        isEmpty = true;
                    }
                    // } else {
                    // logger.error(logger.getPrefix(name.toString(), field)+
                    // "cannot be validated due to wrong number of Qualifiers!", element);
                    // LOG.log(Level.WARNING,
                    // "Validation.validateSpecial(QualificationsType): wrong number of Qualifiers!");
                    // }
                }
                if (isEmpty) {
                    logger.error(logger.getEmptyMessage(name.toString(), QNames._QualificationsQualifiers), element);
                }

                CriteriaListType criteriaList = element.getCriteriaList(); // cannot be null - created in ObjectFiller
                // ecc:CriteriaList assert
                validateSimple(name, QNames._QualificationsAssert, criteriaList.getAssert(), TYPEFORMATS.TEXT,
                        element);

                // ecc:KeyUsage
                boolean foundContent = false;
                List<KeyUsageType> keyUsage = criteriaList.getKeyUsage();
                if (!keyUsage.isEmpty()) {
                    List<KeyUsageBitType> keyUsageBit = keyUsage.get(0).getKeyUsageBit();
                    for (KeyUsageBitType kubit : keyUsageBit) {
                        foundContent = kubit.isValue();
                        if (foundContent) {
                            break;
                        }
                    }
                }

                if (!foundContent) {
                    // ecc:PolicyIdentifier
                    List<PoliciesListType> policySet = criteriaList.getPolicySet();
                    if (!policySet.isEmpty()) {
                        for (PoliciesListType policy : policySet) {
                            List<ObjectIdentifierType> policyIdentifier = policy.getPolicyIdentifier();
                            for (ObjectIdentifierType polId : policyIdentifier) {
                                IdentifierType identifier = polId.getIdentifier();
                                if (identifier != null && identifier.getValue() != null
                                        && !identifier.getValue().isEmpty()) {
                                    foundContent = true;
                                    break;
                                }
                            }
                            if (foundContent) {
                                break;
                            }
                        }
                    }

                    // tslx:ExtendedKeyUsageType & tslx:CertSubjectDNAttributeType
                    eu.europa.ec.markt.tsl.jaxb.xades.AnyType otherCriteriaList = criteriaList
                            .getOtherCriteriaList();
                    List<Object> content = otherCriteriaList.getContent();
                    for (Object obj : content) {
                        if (obj instanceof JAXBElement<?>) {
                            JAXBElement<?> jex = (JAXBElement<?>) obj;
                            if (jex.getName().equals(QNames._ExtendedKeyUsage_QNAME)) {
                                ExtendedKeyUsageType ekut = (ExtendedKeyUsageType) jex.getValue();
                                if (!ekut.getKeyPurposeId().isEmpty()) {
                                    for (ObjectIdentifierType oid : ekut.getKeyPurposeId()) {
                                        if (oid.getIdentifier() != null && !oid.getIdentifier().getValue().isEmpty()) {
                                            foundContent = true;
                                            break;
                                        }
                                    }
                                    if (foundContent) {
                                        break;
                                    }
                                }
                            } else if (jex.getName().equals(QNames._CertSubjectDNAttribute_QNAME)) {
                                CertSubjectDNAttributeType csdat = (CertSubjectDNAttributeType) jex.getValue();
                                if (!csdat.getAttributeOID().isEmpty()) {
                                    for (ObjectIdentifierType oid : csdat.getAttributeOID()) {
                                        if (oid.getIdentifier() != null && !oid.getIdentifier().getValue().isEmpty()) {
                                            foundContent = true;
                                            break;
                                        }
                                    }
                                    if (foundContent) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                if (!foundContent) {
                    logger.error(
                            logger.getPrefix(name.toString(), field)
                                    + uiKeys.getString("Validation.mandatory.qualification.minimumFields"), element);
                }
            }
        }
    }

    // ############################### MANDATORY ###############################
    private void checkMandatoryTSL() {
        if (tsl == null) {
            return;
        }
        try {
            NODENAMES name = NODENAMES.Tsl;
            // tsl:TSLSequenceNumber
            validateSimple(name, QNames._TSLSequenceNumber, schemeInformation.getTSLSequenceNumber(),
                    TYPEFORMATS.NUMBER, tsl);

            // tsl:TSLSequenceNumber
            validateSimple(name, QNames._TSLType_QNAME.getLocalPart(), schemeInformation.getTSLType(),
                    TYPEFORMATS.URL, tsl);

            // tsl:SchemeOperatorName
            validateList(name, QNames._SchemeOperatorName_QNAME.getLocalPart(), schemeInformation
                    .getSchemeOperatorName().getName(), tsl);

            // tsl:SchemeOperatorAddress - tsl:PostalAddresses - tsl:PostalAddress
            validateList(name, QNames._PostalAddress_QNAME.getLocalPart(), schemeInformation
                    .getSchemeOperatorAddress().getPostalAddresses().getPostalAddress(), tsl);

            // tsl:SchemeOperatorAddress - tsl:PostalAddresses - tsl:ElectronicAddress
            validateList(name, QNames._ElectronicAddress_QNAME.getLocalPart(), schemeInformation
                    .getSchemeOperatorAddress().getElectronicAddress().getURI(), tsl);

            // tsl:SchemeName
            validateList(name, QNames._SchemeName_QNAME.getLocalPart(), schemeInformation.getSchemeName().getName(),
                    tsl);

            // tsl:StatusDeterminationApproach
            validateSimple(name, QNames._StatusDeterminationApproach_QNAME.getLocalPart(), schemeInformation.
                  getStatusDeterminationApproach(), TYPEFORMATS.URL, tsl);

            // tsl:SchemeInformationURI
            validateList(name, QNames._SchemeInformationURI_QNAME.getLocalPart(), schemeInformation
                    .getSchemeInformationURI().getURI(), tsl);

            // tsl:SchemeTypeCommunityRules
            validateList(name, QNames._SchemeTypeCommunityRules_QNAME.getLocalPart(), schemeInformation
                    .getSchemeTypeCommunityRules().getURI(), tsl);

            // tsl:SchemeTerritory
            validateSimple(name, QNames._SchemeTerritory_QNAME.getLocalPart(),
                    schemeInformation.getSchemeTerritory(), TYPEFORMATS.TEXT, tsl);

            // tsl:PolicyOrLegalNotice
            validateList(name, QNames._PolicyOrLegalNotice_QNAME.getLocalPart(), schemeInformation
                    .getPolicyOrLegalNotice().getTSLLegalNotice(), tsl);

            // tsl:HistoricalInformationPeriod
            validateSimple(name, QNames._HistoricalInformationPeriod,
                    schemeInformation.getHistoricalInformationPeriod(), TYPEFORMATS.NUMBER, tsl);

            // tsl:ListIssueDateTime
            validateSimple(name, QNames._ListIssueDateTime, schemeInformation.getListIssueDateTime(),
                    TYPEFORMATS.DATE, tsl);

            // tsl:NextUpdate
            if (!vParams.isListIsClosed()) {
                validateSimple(name, QNames._NextUpdate_QNAME.getLocalPart(), schemeInformation.getNextUpdate()
                        .getDateTime(), TYPEFORMATS.DATE, tsl);
            }
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Null Pointer Exception in checkMandatoryTSL() - " + ex.getMessage());
        }
    }

    private void checkMandatoryPointer() {
        if (pointers == null) {
            return;
        }
        try {
            NODENAMES name = NODENAMES.Pointer;
            for (OtherTSLPointerType pointer : pointers) {
                // tsl:ServiceDigitalIdentities
                // Note: at this point, the actual content of the certificate cannot be verified ->
                // just check if there is 'something'...
                validateSpecial(name, pointer.getServiceDigitalIdentities().getServiceDigitalIdentity().get(0),
                        pointer, false);

                // tsl:TSLLocation
                validateSimple(name, QNames._TSLLocation, pointer.getTSLLocation(), TYPEFORMATS.TEXT, pointer);

                // go into <tsl:AdditionalInformation> and find all <tsl:OtherInformation>
                for (Serializable other : pointer.getAdditionalInformation()
                        .getTextualInformationOrOtherInformation()) {
                    if (other instanceof AnyType) {
                        AnyType anyType = (AnyType) other;
                        Object object = anyType.getContent().get(0);
                        if (object instanceof JAXBElement) {
                            JAXBElement<?> element = (JAXBElement<?>) object;
                            if (element.getName().equals(QNames._SchemeOperatorName_QNAME)) {
                                InternationalNamesType list = (InternationalNamesType) element.getValue();
                                validateList(name, QNames._SchemeOperatorName_QNAME.getLocalPart(), list.getName(),
                                        pointer);
                            } else if (element.getName().equals(QNames._SchemeTypeCommunityRules_QNAME)) {
                                if (!Configuration.getInstance().isTlMode()) {
                                    NonEmptyURIListType list = (NonEmptyURIListType) element.getValue();
                                    validateList(name, QNames._SchemeTypeCommunityRules_QNAME.getLocalPart(),
                                            list.getURI(), pointer);
                                }
                            } else if (element.getName().equals(QNames._SchemeTerritory_QNAME)) {
                                validateSimple(name, QNames._SchemeTerritory_QNAME.getLocalPart(),
                                        element.getValue(), TYPEFORMATS.TEXT, pointer);
                            } else if (element.getName().equals(QNames._MimeType_QNAME)) {
                                validateSimple(name, QNames._MimeType_QNAME.getLocalPart(), element.getValue(),
                                        TYPEFORMATS.TEXT, pointer);
                            } else if (element.getName().equals(QNames._TSLType_QNAME)) {
                                validateSimple(name, QNames._TSLType_QNAME.getLocalPart(), element.getValue(),
                                        TYPEFORMATS.URL, pointer);
                            }
                        }
                    }
                }
            }
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Null Pointer Exception in checkMandatoryPointer() - " + ex.getMessage());
        }
    }

    private void checkMandatoryTSP() {
        if (tsps == null) {
            return;
        }
        try {
            NODENAMES name = NODENAMES.Tsp;
            for (TSPType tsp : tsps) {
                TSPInformationType tspInformation = tsp.getTSPInformation();

                // tsl:TSPName
                validateList(name, QNames._TSPName, tspInformation.getTSPName().getName(), tsp);

                // tsl:PostalAddress
                validateList(name, QNames._PostalAddress_QNAME.getLocalPart(), tspInformation.getTSPAddress()
                        .getPostalAddresses().getPostalAddress(), tsp);

                // tsl:ElectronicAddress
                validateList(name, QNames._ElectronicAddress_QNAME.getLocalPart(), tspInformation.getTSPAddress()
                        .getElectronicAddress().getURI(), tsp);

                // tsl:TSPInformationURI
                validateList(name, QNames._TSPInformationURI, tspInformation.getTSPInformationURI().getURI(), tsp);
                
                // check whether there is at least one associated service
                TSPServicesListType tspServices = tsp.getTSPServices();
                if (tspServices != null) {
                    if (tspServices.getTSPService().isEmpty()) {
                        logger.error(uiKeys.getString("Validation.mandatory.atLeastOneService"), tsp);
                    }
                } else {
                    logger.error(uiKeys.getString("Validation.mandatory.atLeastOneService"), tsp);
                }
            }
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Null Pointer Exception in checkMandatoryTSP() - " + ex.getMessage());
        }
    }

    private void checkMandatoryService() {
        if (services == null) {
            return;
        }
        try {
            NODENAMES name = NODENAMES.Service;
            for (TSPServiceType service : services) {
                TSPServiceInformationType serviceInformation = service.getServiceInformation();

                // tsl:ServiceTypeIdentifier
                validateSimple(name, QNames._ServiceTypeIdentifier_QNAME.getLocalPart(),
                        serviceInformation.getServiceTypeIdentifier(), TYPEFORMATS.TEXT, service);

                // tsl:ServiceName
                validateList(name, QNames._ServiceName, serviceInformation.getServiceName().getName(), service);

                // tsl:ServiceDigitalIdentity
                validateSpecial(name, serviceInformation.getServiceDigitalIdentity(), service, false);

                // tsl:ServiceStatus
                validateSimple(name, QNames._ServiceStatus_QNAME.getLocalPart(),
                        serviceInformation.getServiceStatus(), TYPEFORMATS.TEXT, service);

                // tsl:StatusStartingTime
                validateSimple(name, QNames._StatusStartingTime, serviceInformation.getStatusStartingTime(),
                        TYPEFORMATS.DATE, service);
            }
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Null Pointer Exception in checkMandatoryService() - " + ex.getMessage());
        }
    }

    private void checkMandatoryHistory() {
        if (histories == null) {
            return;
        }
        try {
            NODENAMES name = NODENAMES.History;
            for (ServiceHistoryInstanceType history : histories) {

                // tsl:ServiceTypeIdentifier
                validateSimple(name, QNames._ServiceTypeIdentifier_QNAME.getLocalPart(),
                        history.getServiceTypeIdentifier(), TYPEFORMATS.TEXT, history);

                // tsl:ServiceName
                validateList(name, QNames._ServiceName, history.getServiceName().getName(), history);

                // tsl:ServiceDigitalIdentity
                validateSpecial(name, history.getServiceDigitalIdentity(), history, true);

                // tsl:ServiceStatus
                validateSimple(name, QNames._ServiceStatus_QNAME.getLocalPart(), history.getServiceStatus(),
                        TYPEFORMATS.TEXT, history);

                // tsl:StatusStartingTime
                validateSimple(name, QNames._StatusStartingTime, history.getStatusStartingTime(), TYPEFORMATS.DATE,
                        history);
            }
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Null Pointer Exception in checkMandatoryHistory() - " + ex.getMessage());
        }
    }

    private void checkMandatoryExtension() {
        if (extensions == null) {
            return;
        }
        try {
            NODENAMES name = NODENAMES.Extension;
            for (ExtensionsListType extensionsList : extensions) {
                for (ExtensionType extension : extensionsList.getExtension()) {
                    if (!extension.getContent().isEmpty()) {
                        Object content = extension.getContent().get(0);
                        if (content instanceof JAXBElement) {
                            JAXBElement<?> element = (JAXBElement<?>) content;
                            if (element.getName().equals(QNames._TakenOverBy_QNAME)) {
                                TakenOverByType tob = (TakenOverByType) element.getValue();
                                validateSpecial(name, tob, extensionsList);
                            } else if (element.getName().equals(QNames._ExpiredCertsRevocationInfo_QNAME)) {
                                // Note: no need to validate anything here; either the date is specified or not
                            } else if (element.getName().equals(QNames._AdditionalServiceInformation_QNAME)) {
                                AdditionalServiceInformationType asi = (AdditionalServiceInformationType) element
                                        .getValue();
                                validateSpecial(name, asi, extensionsList);
                            } else if (element.getName().equals(QNames._Qualifications_QNAME)) {
                                QualificationsType qual = (QualificationsType) element.getValue();
                                validateSpecial(name, qual);
                            } else {
                                LOG.log(Level.WARNING, "Validation.checkMandatoryExtension(): "
                                        + "There is an unexpected object: " + element.getName());
                            }
                        }
                    }
                }
            }
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Null Pointer Exception in checkMandatoryExtension() - " + ex.getMessage());
        }
    }

    // ############################### RULES ###############################
    // Note: all mandatory fields have been checked before -> several null checks are omitted
    /**
     * IssueDate must not be ulterior to the current time.
     */
    private void checkRuleIssueDate() {
        GregorianCalendar listIssueTime = schemeInformation.getListIssueDateTime().toGregorianCalendar();
        GregorianCalendar gc = new GregorianCalendar();
        int result = listIssueTime.compareTo(gc);
        if (result == 1) {
            logger.warn(uiKeys.getString("Validation.rule.issueDate"), tsl);
        }
    }

    /**
     * If Nextupdate is not empty, the difference between IssuedDate and NextUpdate cannot exceed 6 months.
     */
    private void checkRuleNextUpdate() {
        NextUpdateType nextUpdate = schemeInformation.getNextUpdate();
        String nuName = QNames._NextUpdate_QNAME.getLocalPart(), liName = QNames._ListIssueDateTime;
        if (nextUpdate != null && nextUpdate.getDateTime() != null) {
            GregorianCalendar nextUpdateTime = nextUpdate.getDateTime().toGregorianCalendar();
            GregorianCalendar listIssueTime = schemeInformation.getListIssueDateTime().toGregorianCalendar();
            if (nextUpdateTime.before(listIssueTime)) {
                logger.error(nuName + uiKeys.getString("Validation.rule.nextUpdate.mustBeLater") + liName + "!", tsl);
            } else {
                GregorianCalendar gc = (GregorianCalendar) listIssueTime.clone();
                gc.add(Calendar.MONTH, 6);
                if (gc.before(nextUpdateTime)) {
                    logger.error(uiKeys.getString("Validation.rule.nextUpdate.dontExceed6Months") + liName + " - "
                            + nuName + "!", tsl);
                }
            }
        }
    }

    /**
     * The SequenceNumber must be an integer and equal or greater than 1.
     */
    private void checkRuleSequenceNumberFormat() {
        BigInteger tslSequenceNumber = schemeInformation.getTSLSequenceNumber();
        if (tslSequenceNumber.intValue() < 1) {
            logger.error(QNames._TSLSequenceNumber + uiKeys.getString("Validation.rule.sequenceNumberFormat"), tsl);
        }
    }

    /**
     * The scheme name must be a string structured as follows: CC:name_value Where CC = the ISO 3166-1 alpha-2 Country
     * Code used in the field "Territory"; Name_value = the text filled by the user and describing the name of the
     * scheme.
     */
    private void checkRuleSchemeName() {
        InternationalNamesType schemeName = schemeInformation.getSchemeName();
        boolean error = false;
        for (MultiLangNormStringType names : schemeName.getName()) {
            String value = names.getValue();
            String[] split = value.split(":");
            if (split.length < 2) {
                error = true;
                break;
            }
            CountryCodes countryCodes = Configuration.getInstance().getCountryCodes();
            if (!countryCodes.getCodesList().contains(split[0])) {
                error = true;
                break;
            }
        }
        if (error) {
            logger.error(
                    uiKeys.getString("Validation.rule.schemeName.part1") + QNames._SchemeName_QNAME.getLocalPart()
                            + uiKeys.getString("Validation.rule.schemeName.part2"), tsl);
        }
    }

    /**
     * The field HistoricalPeriod must be equal to 65535
     */
    private void checkRuleHistoricalPeriod() {
        BigInteger historicalInformationPeriod = schemeInformation.getHistoricalInformationPeriod();
        String name = QNames._HistoricalInformationPeriod;
        BigInteger fixedValue = Configuration.getInstance().getHistoricalInformationPeriod();

        if (historicalInformationPeriod.intValue() != fixedValue.intValue()) {
            logger.error(name + uiKeys.getString("Validation.rule.historicalPeriod") + " " + fixedValue + "!", tsl);
        }
    }

    /**
     * If the type of the TSL is 'generic', the number of pointer to other TSL must be equal to 2.
     */
    private void checkRulePointerToOtherTSL() {
        if (Configuration.getInstance().isTlMode()) {
            if (pointers == null || pointers.size() != 2) {
                logger.error(uiKeys.getString("Validation.rule.pointerToOtherTSL.tl"));
            }
        }
    }

    /**
     * If Type = "generic", there must be at least 2 URIs in TypeCommunityRule. If Type = "schemes", there must be only
     * 1 URI in TypeCommunityRule. Note: This check is done with values from the TSL page
     *
     * Note: this check is done reading the starting mode of the application (not with tsl.schemeInformation.tslType)
     */
    private void checkRuleTypeCommunityRule() {
        String name = QNames._SchemeTypeCommunityRules_QNAME.getLocalPart();
        NonEmptyMultiLangURIListType schemeTypeCommunityRules = schemeInformation.getSchemeTypeCommunityRules();
        List<NonEmptyMultiLangURIType> uris = schemeTypeCommunityRules.getURI();
        if (Configuration.getInstance().isTlMode()) {
            if (uris.size() < 2) {
                logger.error(name + uiKeys.getString("Validation.rule.typeCommunityRule.tl"), tsl);
            }
        } else if (uris.size() != 1) {
            logger.error(name + uiKeys.getString("Validation.rule.typeCommunityRule.lotl"), tsl);
        }
    }

    /**
     * Verify that tsl.schemeInformation.tslType is inline with the mode of the application and the country selected
     */
    void checkRuleSchemaInformationTSLType() {
        String name = QNames._TSLType_QNAME.getLocalPart();
        final String tslType = tsl.getSchemeInformation().getTSLType();
        final String schemeTerritory = tsl.getSchemeInformation().getSchemeTerritory();
        if (Configuration.getInstance().getCountryCodes().isCodeInList(schemeTerritory)) {
            // eu country, TSL Type value is fixed
            if (!tslType.equals(Configuration.getInstance().getTSL().getTslType())) {
                logger.error(name + uiKeys.getString("Validation.rule.tslType.inverse"), tsl);
            }
        }
    }

    /**
     * Verify that if tsl.schemeInformation.tslType is
     * "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClist" or "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClistofthelists"
     * the "CC" value is equals to tsl.schemeInformation.schemeTerritory
     */
    void checkRuleSchemeTerritoryInUpperCase() {
        String nameTerritory = QNames._SchemeTerritory_QNAME.getLocalPart();
        final String territory = tsl.getSchemeInformation().getSchemeTerritory();
        if (!territory.toUpperCase().equals(territory)) {
            logger.error(nameTerritory + uiKeys.getString("Validation.rule.schemeTerritory.uppercase"), tsl);
        }
    }

    /**
     * Verify that if tsl.schemeInformation.tslType is
     * "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClist" or "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClistofthelists"
     * the "CC" value is equals to tsl.schemeInformation.schemeTerritory
     */
    void checkRuleSchemaInformationTSLTypeInlineWithSchemeTerritory() {
        String name = QNames._TSLType_QNAME.getLocalPart();
        final String tslType = tsl.getSchemeInformation().getTSLType();
        final String schemeTerritory = tsl.getSchemeInformation().getSchemeTerritory();
        if (!Configuration.getInstance().getCountryCodes().isCodeInList(schemeTerritory)) {
            final String tslTypeNonEu = Configuration.getInstance().getTSL().getTslType();
            String regExp = tslTypeNonEu.replaceAll("(#CC#)", "(.+)");
            final Pattern pattern = Pattern.compile(regExp);
            final Matcher matcher = pattern.matcher(tslType);
            if (matcher.matches()) {
                final String countryInTslType = matcher.group(1);
                if (!countryInTslType.equals(schemeTerritory)) {
                    logger.error(name + uiKeys.getString("Validation.rule.tslType.country.matcherror"), tsl);
                }
            }
        } else {
           // checked in checkRuleSchemaInformationTSLType
        }
    }

    /**
     * If the scheme type is "generic/list", the TSLType of the pointer to other TSL must be "listofthelists". And vice
     * et versa.
     */
    void checkRuleTSLType() {
            String name = QNames._TSLType_QNAME.getLocalPart();

        final String schemeTerritory = tsl.getSchemeInformation().getSchemeTerritory();
        if (Configuration.getInstance().getCountryCodes().isCodeInList(schemeTerritory)) {
            String tslTypeInverseEu = Configuration.getInstance().getTSL().getTslTypeInverse();
            if (pointers != null) {
                for (OtherTSLPointerType pointer : pointers) {
                    List<Serializable> othInfo = pointer.getAdditionalInformation()
                          .getTextualInformationOrOtherInformation();
                    String tslType = "";
                    for (Serializable obj : othInfo) {
                        if (obj instanceof AnyType) {
                            AnyType anyType = (AnyType) obj;
                            List<Object> content = anyType.getContent();
                            if (!content.isEmpty() && content.get(0) instanceof JAXBElement<?>) {
                                JAXBElement<?> element = (JAXBElement<?>) content.get(0);
                                if (element.getName().getLocalPart().equals(name)) {
                                    tslType = (String) element.getValue();
                                    break;
                                }
                            }
                        }
                    }
                    if (tslType.isEmpty() || !tslType.equals(tslTypeInverseEu)) {
                        logger.error(uiKeys.getString("Validation.rule.tslType.allPointersMustHave") + name + ": " + tslTypeInverseEu, pointer);
                    }
                }
            }
        }
    }

    /**
     * If TSLType = "schemes" (lotl), SchemeTerritory must be "EU".
     */
    void checkRuleSchemeTerritory() {
        String nameTSLType = QNames._TSLType_QNAME.getLocalPart();
        String nameTerritory = QNames._SchemeTerritory_QNAME.getLocalPart();
        String schemesTSLType = Configuration.getInstance().getLotlTslTypeEu();

        if (pointers != null) {
            for (OtherTSLPointerType pointer : pointers) {
                List<Serializable> othInfo = pointer.getAdditionalInformation()
                      .getTextualInformationOrOtherInformation();
                String tslType = "";
                String territory = "";
                for (Serializable obj : othInfo) {
                    if (obj instanceof AnyType) {
                        AnyType anyType = (AnyType) obj;
                        List<Object> content = anyType.getContent();
                        if (!content.isEmpty() && content.get(0) instanceof JAXBElement<?>) {
                            JAXBElement<?> element = (JAXBElement<?>) content.get(0);
                            if (element.getName().getLocalPart().equals(nameTSLType)) {
                                tslType = (String) element.getValue();
                            } else if (element.getName().getLocalPart().equals(nameTerritory)) {
                                territory = (String) element.getValue();
                            }
                        }
                    }
                }

                // check that the territory code is in uppercase
                if (!territory.toUpperCase().equals(territory)) {
                    logger.error(nameTerritory + uiKeys.getString("Validation.rule.schemeTerritory.uppercase"), pointer);
                }

                // check that the EUlistofthelist is used only for territory EU
                if (tslType.equals(schemesTSLType)) {
                    if (!territory.equals("EU")) {
                        logger.error(uiKeys.getString("Validation.rule.schemeTerritory.eu"), pointer);
                    }
                }

                if (!Configuration.getInstance().getCountryCodes().isCodeInList(territory)) {
                    final String tslTypeInverseNonEu = Configuration.getInstance().getTSL().getTslTypeInverse();
                    String regExp = tslTypeInverseNonEu.replaceAll("(#CC#)", "(.+)");
                    final Pattern pattern = Pattern.compile(regExp);
                    final Matcher matcher = pattern.matcher(tslType);
                    if (matcher.matches()) {
                        final String countryInTslType = matcher.group(1);
                        if (!countryInTslType.equals(territory)) {
                            logger.error(nameTerritory + uiKeys.getString("Validation.rule.tslType.country.matcherror"), pointer);
                        }
                    }
                }
            }
        }
    }

    /**
     * If TSLType = "generic", there must be at least 2 URIs in SchemeTypeCommunityRule. If TSLType = "schemes", there
     * must be only 1 URI in SchemeTypeCommunityRule. Note: This check is done on each pointer; the current tsl type is
     * 'generic' if its pointers have a type of 'schemes' and vice versa
     */
    private void checkRuleSchemeTypeCommunityRule() {
        String name = QNames._SchemeTypeCommunityRules_QNAME.getLocalPart();
        String nameTSLType = QNames._TSLType_QNAME.getLocalPart();
        String nameTerritory = QNames._SchemeTerritory_QNAME.getLocalPart();

        if (pointers != null) {
            for (OtherTSLPointerType pointer : pointers) {
                List<Serializable> othInfo = pointer.getAdditionalInformation()
                        .getTextualInformationOrOtherInformation();
                String tslType = "";
                String territory = "";
                NonEmptyMultiLangURIListType communityRules = null;
                for (Serializable obj : othInfo) {
                    if (obj instanceof AnyType) {
                        AnyType anyType = (AnyType) obj;
                        List<Object> content = anyType.getContent();
                        if (!content.isEmpty() && content.get(0) instanceof JAXBElement<?>) {
                            JAXBElement<?> element = (JAXBElement<?>) content.get(0);
                            if (element.getName().getLocalPart().equals(nameTSLType)) {
                                tslType = (String) element.getValue();
                            } else if (element.getName().getLocalPart().equals(name)) {
                                communityRules = (NonEmptyMultiLangURIListType) element.getValue();
                            } else if (element.getName().getLocalPart().equals(nameTerritory)) {
                                territory = (String) element.getValue();
                            }
                        }
                    }
                }

                if (Configuration.getInstance().getCountryCodes().isCodeInList(territory)) {
                    // eu country
                    boolean isLotlTslType = tslType.equals(Configuration.getInstance().getLotlTslTypeEu());
                    boolean isTlTslType = tslType.equals(Configuration.getInstance().getTlTslTypeEu());

                    if (isLotlTslType) { // schemes
                        if (communityRules != null && communityRules.getURI().size() != 1) {
                            logger.error(name + uiKeys.getString("Validation.rule.schemeTypeCommunityRule.lotl"),
                                  pointer);
                        }
                    } else {
                        if (isTlTslType) {
                            if (communityRules != null && communityRules.getURI().size() < 2) {
                                logger.error(name + uiKeys.getString("Validation.rule.schemeTypeCommunityRule.tl"),
                                      pointer);
                            }
                        }
                    }

                } else {
                    // no check done if non-eu country
                }
            }
        }
    }

    /**
     * 5.5.3 Service digital identity
     * <p/>
     * The same public key (and hence the same certificate representing this public key) shall not appear
     * more than once in the trusted list for the same type of service. The same public key may appear
     * more than once in the TL only when associated to trust services having different 'Service type
     * identifier' ('Sti') values (e.g. public key used for verifying signatures on different types of Trust
     * Services Tokens) for which different supervision/ accreditation systems apply.
     */
    private void checkRuleUniqueSDIperService() {
        if (services != null) {
            Set<String> keySet = new HashSet<String>();
            for (TSPServiceType service : services) {
                // both values are mandatory and are supposed to be present at this point
                String sti = service.getServiceInformation().getServiceTypeIdentifier();
                DigitalIdentityListType sdi = service.getServiceInformation().getServiceDigitalIdentity();
                byte[] publicKey = null;
                for (DigitalIdentityType id : sdi.getDigitalId()) { // 1-2 entries
                    if (publicKey == null) {
                        try {
                            byte[] x509Certificate = id.getX509Certificate();
                            final X509Certificate x509 = DSSUtils.loadCertificate(x509Certificate);
                            publicKey = x509.getPublicKey().getEncoded();
                            continue;
                        } catch (DSSException e) {
                            LOG.log(Level.SEVERE, e.getMessage(), e);
                        }
                    } else {
                        break;
                    }
                }
                String couple = sti + Arrays.hashCode(publicKey);
                if (keySet.contains(couple)) {
                    logger.error(uiKeys.getString("Validation.rule.uniqueSDIperService"), service);
                } else {
                    keySet.add(couple);
                }
            }
        }
    }

    /**
     * 5.5.3 Service digital identity
     * <p/>
     * The TLSO may list more than one certificate to represent the
     * public key, but only when all those certificates relate to the same public key and have identical
     * subject names
     */
    void checkRuleAllSDIHaveTheSamePublicKey() {
        if (services != null) {
            for (TSPServiceType service : services) {
                // both values are mandatory and are supposed to be present at this point
                DigitalIdentityListType sdi = service.getServiceInformation().getServiceDigitalIdentity();
                Set<PublicKey> publicKeySet = new HashSet<PublicKey>();
                Set<X500Principal> subjectSet = new HashSet<X500Principal>();
                for (DigitalIdentityType id : sdi.getDigitalId()) { // 1-2 entries
                    byte[] x509Certificate = id.getX509Certificate();
                    if (x509Certificate != null) {
                        try {
                            final X509Certificate x509 = DSSUtils.loadCertificate(x509Certificate);
                            publicKeySet.add(x509.getPublicKey());
                            subjectSet.add(x509.getSubjectX500Principal());
                        } catch (DSSException e) {
                            LOG.log(Level.SEVERE, e.getMessage(), e);
                        }
                    } else {
                        final String x509SubjectName = id.getX509SubjectName();
                        if (x509SubjectName != null){
                            subjectSet.add(new X500Principal(x509SubjectName));
                        }
                    }
                }

                if (publicKeySet.size() > 1) {
                    logger.error(uiKeys.getString("Validation.rule.digitalIdentity.uniquePublicKeyPerService"),
                          service);
                }
                if (subjectSet.size() > 1) {
                    logger.error(uiKeys.getString("Validation.rule.digitalIdentity.uniqueSubjectNamePerService"),
                          service);
                }
            }
        }
    }

    /**
     * 5.5.3 Service digital identity
     * <p/>
     * The TLSO may list more than one certificate to represent the
     * public key, but only when all those certificates relate to the same public key and have identical
     * subject names
     */
    void checkRulePointerToOtherTSLHaveTheSamePublicKey() {
        if (pointers != null) {
            for (OtherTSLPointerType pointer : pointers) {
                final List<DigitalIdentityListType> serviceDigitalIdentity = pointer.getServiceDigitalIdentities()
                      .getServiceDigitalIdentity();
                for (DigitalIdentityListType digitalIdentityListType : serviceDigitalIdentity) {
                    Set<PublicKey> publicKeySet = new HashSet<PublicKey>();
                    Set<X500Principal> subjectSet = new HashSet<X500Principal>();
                    for (DigitalIdentityType id : digitalIdentityListType.getDigitalId()) { // 1-2 entries
                        byte[] x509Certificate = id.getX509Certificate();
                        if (x509Certificate != null) {
                            try {
                                final X509Certificate x509 = DSSUtils.loadCertificate(x509Certificate);
                                publicKeySet.add(x509.getPublicKey());
                                subjectSet.add(x509.getSubjectX500Principal());
                            } catch (DSSException e) {
                                LOG.log(Level.SEVERE, e.getMessage(), e);
                            }
                        }
                    }

                    if (publicKeySet.size() > 1) {
                        logger.error(uiKeys.getString("Validation.rule.digitalIdentity.uniquePublicKeyPerService"),
                              pointer);
                    }
                    if (subjectSet.size() > 1) {
                        logger.error(uiKeys.getString("Validation.rule.digitalIdentity.uniqueSubjectNamePerService"),
                              pointer);
                    }
                }
            }
        }
    }

    /**
     * 5.3.5.2
     * A sequence of multilingual character strings (see clause 5.1.4) giving:
     * *   e-mail address as a URI, in the form specified by RFC 3986 [9], with the URI scheme
     * defined in RFC 2368 [7]; and
     * *   web-site as a URI, in the form specified by RFC 3986 [9].
     * Both character strings shall be present.
     */
    void checkRuleSchemeOperatorElectronicAddress() {
        final String name = QNames._ElectronicAddress_QNAME.getLocalPart();
        final ElectronicAddressType electronicAddress = tsl.getSchemeInformation().getSchemeOperatorAddress()
              .getElectronicAddress();
        boolean valid = electronicAddressHasEmailAndWeb(electronicAddress);
        if (!valid){
            logger.error(name + uiKeys.getString("Validation.rule.schemeoperatoraddress"), tsl);
        }
    }

    private boolean electronicAddressHasEmailAndWeb(ElectronicAddressType electronicAddress) {
        final List<NonEmptyMultiLangURIType> uris = electronicAddress.getURI();
        // list must contains both email and http
        boolean emailPresent = false;
        boolean webPresent = false;
        for (NonEmptyMultiLangURIType uri : uris) {
            if (uri.getValue().startsWith("mailto:")){
                emailPresent = true;
            } else if (uri.getValue().startsWith("http://") || uri.getValue().startsWith("https://")){
                webPresent = true;
            }
            if (emailPresent && webPresent){
                break;
            }
        }
        return emailPresent && webPresent;
    }

    /**
     * 5.3.8 Status Determination Approach
     *
     * In the context of EU Member State trusted lists, the URI shall be set to
     "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/StatusDetn/EUappropriate" as defined in
     clause D.5.
     TLSOs from non-EU countries and international organizations shall use either:
     the "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/StatusDetn/CCdetermination" URI as
     defined in clause D.6 and where "CC" is replaced by the code used in the 'Scheme territory
     field' (clause 5.3.10); or
     a URI defined on purpose or registered under ETSI Identified Organization Domain as
     described in clause D.3 of the present document.
     */
    void checkRuleStatusDeterminationApproach() {
        final String name = QNames._StatusDeterminationApproach_QNAME.getLocalPart();
        final String schemeTerritory = tsl.getSchemeInformation().getSchemeTerritory();
        final String statusDeterminationApproach = tsl.getSchemeInformation().getStatusDeterminationApproach();
        final String tslStatusDeterminationApproach = Configuration.getInstance().getTSL()
              .getTslStatusDeterminationApproach();
        if (Configuration.getInstance().getCountryCodes().isCodeInList(schemeTerritory)) {
            // EU country
            if (!tslStatusDeterminationApproach.equals(statusDeterminationApproach)) {
                logger.error(name + uiKeys.getString("Validation.rule.statusDeterminationApproach"), tsl);
            }
        } else {
            // non EU country
            if (tslStatusDeterminationApproach.equals(statusDeterminationApproach)) {
                logger.error(name + uiKeys.getString("Validation.rule.statusDeterminationApproach"), tsl);
            } else {
                Pattern pattern = Pattern.compile(tslStatusDeterminationApproach.replaceAll("#CC#", "(.+)"));
                final Matcher matcher = pattern.matcher(statusDeterminationApproach);
                if (matcher.matches()) {
                    final String countryInStatusDeterminationApproach = matcher.group(1);
                    if (!countryInStatusDeterminationApproach.equals(schemeTerritory)) {
                        logger.error(
                              name + uiKeys.getString("Validation.rule.statusDeterminationApproach.country.matcherror"),
                              tsl);
                    }
                }
            }
        }
    }

    /**
     * 5.3.17 Scheme extensions
     Presence: This field shall not be present for EU Member States' trusted lists. It is optional for non-EU
     countries and international organizations.
     */
    void checkRuleSchemeInformationSchemeExtensions() {
        final QName name = QNames._SchemeExtensions_QNAME;
        final ExtensionsListType schemeExtensions = tsl.getSchemeInformation().getSchemeExtensions();
        final String schemeTerritory = tsl.getSchemeInformation().getSchemeTerritory();
        if (Configuration.getInstance().getCountryCodes().isCodeInList(schemeTerritory)) {
            if (schemeExtensions != null && schemeExtensions.getExtension() != null && !schemeExtensions.getExtension()
                  .isEmpty()) {
                logger.error(name + uiKeys.getString("Validation.rule.schemeInformation.schemeExtensions"), tsl);
            }
        }
    }

    void checkRuleTSPElectronicAddress() {
        final QName name = QNames._ElectronicAddress_QNAME;
        final TrustServiceProviderListType trustServiceProviderList = tsl.getTrustServiceProviderList();
        if (trustServiceProviderList != null) {
            final List<TSPType> trustServiceProviderListList = trustServiceProviderList.getTrustServiceProvider();
            if (trustServiceProviderListList != null) {
                for (TSPType tsp : trustServiceProviderListList) {
                    final ElectronicAddressType electronicAddress = tsp.getTSPInformation().getTSPAddress()
                          .getElectronicAddress();
                    boolean valid = electronicAddressHasEmailAndWeb(electronicAddress);
                    if (!valid) {
                        logger.error(name + uiKeys.getString("Validation.rule.tsp.address"), tsp);
                    }
                }
            }
        }
    }


    /*
     * Returns true if all the given ExtensionType have an empty asi
     */
    private boolean isAsiEmpty(List<ExtensionType> extension) {
        if (!extension.isEmpty()) {
            for (ExtensionType exType : extension) {
                JAXBElement<?> asiElement = Util.extractJAXBElement(exType);
                Object asiValue = asiElement.getValue();
                if (asiValue != null) {
                    AdditionalServiceInformationType asi = (AdditionalServiceInformationType) asiValue;

                    if ((asi.getInformationValue() != null && !asi.getInformationValue().isEmpty())
                            || (asi.getURI() != null && asi.getURI().getValue() != null
                                    && !asi.getURI().getValue().isEmpty() && !asi.getURI().getValue()
                                    .equals(Util.DEFAULT_NO_SELECTION_ENTRY))) {
                        return false; // it's enough to find just one
                    }
                }

            }
        }

        return true;
    }

    /**
     * If present, the service information extensions list must contain at least one extension.
     * <p>
     * Note: As soon there is something different than having a tob and ecri extensionType, the extensionList for a
     * service is not considered to be empty anymore.
     * <p>
     * Note2: this checks on all available extensions at the same time (Service and History).
     */
    private void checkRuleServiceInformationExtensions() {
        if (extensions != null) {
            for (ExtensionsListType extensionList : extensions) {
                List<ExtensionType> tobExtensions = Util.extractMatching(extensionList,
                        QNames._TakenOverBy_QNAME.getLocalPart(), false);
                List<ExtensionType> ecriExtensions = Util.extractMatching(extensionList,
                        QNames._ExpiredCertsRevocationInfo_QNAME.getLocalPart(), false);
                List<ExtensionType> asiExtensions = Util.extractMatching(extensionList,
                        QNames._AdditionalServiceInformation_QNAME.getLocalPart(), false);
                List<ExtensionType> qualExtensions = Util.extractMatching(extensionList,
                        QNames._Qualifications_QNAME.getLocalPart(), false);

                boolean asiEmpty = isAsiEmpty(asiExtensions);
                // Note: With a single qualification extension, it is considered to be content for the extension,
                // although it may be, that the qualification page does not contain any content too.
                // However, this is not taken into account for this rule!
                if (qualExtensions.size() == 0 && asiEmpty && tobExtensions.size() == 1
                        && ecriExtensions.size() == 1) {
                    boolean tobEmpty = false, ecriEmpty = false;
                    JAXBElement<?> tobElement = Util.extractJAXBElement(tobExtensions.get(0));
                    Object tobValue = tobElement.getValue();
                    if (tobValue != null) {
                        TakenOverByType tob = (TakenOverByType) tobValue;
                        if ((tob.getURI().getValue() == null || tob.getURI().getValue().isEmpty())
                                && tob.getTSPName().getName().isEmpty()
                                && tob.getSchemeOperatorName().getName().isEmpty()
                                && (tob.getSchemeTerritory().isEmpty() || tob.getSchemeTerritory().equals(
                                        Util.DEFAULT_NO_SELECTION_ENTRY))) {
                            tobEmpty = true; // everyhing is empty/null
                        }
                    }

                    JAXBElement<?> ecriElement = Util.extractJAXBElement(ecriExtensions.get(0));
                    Object ecriValue = ecriElement.getValue();
                    if (ecriValue == null) {
                        ecriEmpty = true;
                    }
                    if (tobEmpty && ecriEmpty) {
                        logger.error(uiKeys.getString("Validation.rule.ServiceInformationExtensions"), extensionList);
                    }
                }
            }
        }
    }

    /**
     * The CurrentStatusStartingDate must be greater than the time present in the PreviousStatusStartingDate within the
     * most recent ServiceHistory instance if the status is different.
     */
    private void checkRuleCurrentStatusStartingDate() {
        if (services != null) {
            for (TSPServiceType service : services) {
                GregorianCalendar serviceTime = service.getServiceInformation().getStatusStartingTime()
                        .toGregorianCalendar();
                // serviceTime can't be null at this point
                ServiceHistoryType serviceHistory = service.getServiceHistory();
                if (serviceHistory != null) {
                    List<ServiceHistoryInstanceType> serviceHistoryInstance = serviceHistory
                            .getServiceHistoryInstance();
                    for (ServiceHistoryInstanceType history : serviceHistoryInstance) {
                        GregorianCalendar historyTime = history.getStatusStartingTime().toGregorianCalendar();
                        if (historyTime.after(serviceTime)) {
                            logger.error(uiKeys.getString("Validation.rule.currentStatusStartingDate"), history);
                        }
                    }
                }
            }
        }
    }

    /**
     * History <p> The service type identifier in the ServiceHistory entity must refer to the type identifier described in
     * the Service entity.
     */
    private void checkRuleServiceTypeIdentifier() {
        if (services != null) {
            for (TSPServiceType service : services) {
                String serviceSTI = service.getServiceInformation().getServiceTypeIdentifier();
                ServiceHistoryType serviceHistory = service.getServiceHistory();
                if (serviceHistory != null) {
                    List<ServiceHistoryInstanceType> serviceHistoryInstance = serviceHistory
                            .getServiceHistoryInstance();
                    for (ServiceHistoryInstanceType history : serviceHistoryInstance) {
                        String historySTI = history.getServiceTypeIdentifier();
                        if (!serviceSTI.equals(historySTI)) {
                            logger.error(uiKeys.getString("Validation.rule.serviceTypeIdentifier"), history);
                        }
                    }
                }
            }
        }
    }

    /**
     * History
     * <p>
     * The service digital identifier must refer to the SDI described in the Service entity.
     */
    private void checkRuleServiceDigitalIdentifier() {
        if (services != null) {
            for (TSPServiceType service: services) {
                DigitalIdentityListType sdi = service.getServiceInformation().getServiceDigitalIdentity();
                
                byte[] certS = null, skiS = null;
                X500Principal subjectName = null;
                for (DigitalIdentityType dit: sdi.getDigitalId()) {
                    if (dit.getX509Certificate() != null) {
                        certS = dit.getX509Certificate();
                        break;  // get only the certificate
                    }
                }
                
                X509Certificate certificate = null;
                try {
                    certificate = DSSUtils.loadCertificate(new ByteArrayInputStream(certS));

                    subjectName = certificate.getSubjectX500Principal();
                    skiS = DSSUtils.getSki(certificate);
                } catch (Exception ex) {    // catch also potential npe's
                    String message = uiKeys.getString("Validation.mandatory.certificate.invalid");
                    LOG.log(Level.SEVERE, message+" - "+ex.getMessage());
                    logger.error(message, service);
                }
                
                ServiceHistoryType serviceHistory = service.getServiceHistory();
                if (serviceHistory != null) {
                    List<ServiceHistoryInstanceType> serviceHistoryInstance = serviceHistory
                            .getServiceHistoryInstance();
                    for (ServiceHistoryInstanceType history: serviceHistoryInstance) {
                        sdi = history.getServiceDigitalIdentity();
                        
                        byte[] certH = null, skiH = null;
                        X500Principal nameH = null;
                        for (DigitalIdentityType dit: sdi.getDigitalId()) {
                            if (dit.getX509Certificate() != null) {
                                certH = dit.getX509Certificate();
                            } else if (dit.getX509SubjectName() != null) {
                                nameH = new X500Principal(dit.getX509SubjectName());
                            } else if (dit.getX509SKI() != null) {
                                skiH = dit.getX509SKI();
                            }
                        }
                        if (certH != null && !Arrays.equals(certH, certS)) {
                            logger.error(uiKeys.getString("Validation.rule.serviceDigitalIdentifier.certMismatch"), history);
                        }
                        
                        if (nameH != null && !nameH.equals(subjectName)) {
                            logger.error(uiKeys.getString("Validation.rule.serviceDigitalIdentifier.snMismatch"), history);
                        }

                        if (skiH != null && skiS != null) {
                            byte[] shorterSki = skiH;
                            byte[] longerSki = skiS;
                            if (skiH.length != skiS.length) {
                                if (skiH.length > skiS.length) {
                                    shorterSki = skiS;
                                    longerSki = skiH;
                                }
                                longerSki = Arrays.copyOfRange(longerSki, longerSki.length - shorterSki.length, longerSki.length);
                            }
                            if (!Arrays.equals(shorterSki, longerSki)) {
                                logger.error(uiKeys.getString("Validation.rule.serviceDigitalIdentifier.skiMismatch"), history);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * History <p> The PreviousStatusStartingDate in the ServiceHistory instance must be greater than the time within the
     * previous ServiceHistory instance if the status indicated in both instances are different. Note: this rule checks
     * that no two histories with the same date/time may have the same status.
     */
    private void checkRulePreviousStatusStartingDate() {
        if (services != null) {
            Map<String, ServiceHistoryInstanceType> map = new HashMap<String, ServiceHistoryInstanceType>();
            int i = 0;
            for (TSPServiceType service : services) {
                ServiceHistoryType serviceHistory = service.getServiceHistory();
                if (serviceHistory != null) {
                    List<ServiceHistoryInstanceType> serviceHistoryInstance = serviceHistory
                            .getServiceHistoryInstance();
                    if (serviceHistoryInstance.size() > 1) {
                        for (ServiceHistoryInstanceType history : serviceHistoryInstance) {
                            String key = i+"-"+history.getStatusStartingTime() + history.getServiceStatus();
                            if (map.containsKey(key)) {
                                logger.error(uiKeys.getString("Validation.rule.previousStatusStartingDate"), history);
                            } else {
                                map.put(key, history);
                            }
                        }
                    }
                }
                i++;
            }
        }
    }

    private class SortableHistory implements Comparable<SortableHistory> {
        private ServiceHistoryInstanceType history;

        /**
         * The default constructor for SortableHistory.
         * 
         * @param history
         */
        public SortableHistory(ServiceHistoryInstanceType history) {
            this.history = history;
        }

        /**
         * @return the history
         */
        public ServiceHistoryInstanceType getHistory() {
            return history;
        }

        /**
         * @return the service status
         */
        public String getServiceStatus() {
            return history.getServiceStatus();
        }

        /** @{inheritDoc */
        @Override
        public int compareTo(SortableHistory o) {
            GregorianCalendar ownCal = history.getStatusStartingTime().toGregorianCalendar();
            GregorianCalendar othCal = o.getHistory().getStatusStartingTime().toGregorianCalendar();

            return ownCal.compareTo(othCal);
        }
    }

    /**
     * History <p> If service history is present, the service current status must follow the status flow described in Study
     * on Cross-Border Interoperability of eSignatures (CROBIES) cf. class <code>StatusInformationFlow</code>
     */
    private void checkRuleServiceCurrentStatusWithServiceHistory() {
        if (services != null) {
            for (TSPServiceType service : services) {
                TSPServiceInformationType serviceInfo = service.getServiceInformation();
                List<SortableHistory> sortedList = new ArrayList<SortableHistory>(); // first element is the oldest one
                ServiceHistoryType serviceHistory = service.getServiceHistory();
                if (serviceHistory != null) {
                    List<ServiceHistoryInstanceType> serviceHistoryInstance = serviceHistory
                            .getServiceHistoryInstance();
                    for (ServiceHistoryInstanceType history : serviceHistoryInstance) {
                        sortedList.add(new SortableHistory(history));
                    }
                    Collections.sort(sortedList);

                    StatusInformationFlow statusInformationFlow = new StatusInformationFlow();
                    if (statusInformationFlow.isInitError()) {
                        logger.warn(uiKeys.getString("Validation.rule.serviceCurrentStatus.initError"), service);
                        continue;
                    }

                    if (!sortedList.isEmpty()) {
                        // thx to checkRuleCurrentStatusStartingDate() service has the most recent date ...
                        // ... but still this is not guaranteed here so it must be checked again
                        ServiceHistoryInstanceType lastHistory = sortedList.get(sortedList.size() - 1).getHistory();
                        boolean tru = Util.isFirstDateEarlierOrEqualThanSecond(lastHistory.getStatusStartingTime(),
                                serviceInfo.getStatusStartingTime());

                        if (!tru) {
                            logger.error(uiKeys.getString("Validation.rule.serviceCurrentStatus.needLatestTime"),
                                    service);
                            continue; // next service
                        }
                    }

                    // now check for a correct start status
                    String startStatusToCheck = "";
                    Object reference = null;
                    if (!sortedList.isEmpty()) {
                        ServiceHistoryInstanceType serviceHistoryInstanceType = sortedList.get(0).getHistory(); // oldest
                                                                                                                // entry
                        startStatusToCheck = serviceHistoryInstanceType.getServiceStatus();
                        reference = serviceHistoryInstanceType;
                    } else {
                        startStatusToCheck = serviceInfo.getServiceStatus();
                        reference = service;
                    }
                    Status status = statusInformationFlow.getMatchingStatus(startStatusToCheck);
                    if (status != null && !status.isStartPoint()) {
                        logger.error(
                                uiKeys.getString("Validation.rule.serviceCurrentStatus.missingValidStartStatus"),
                                reference);
                        continue;
                    }

                    boolean foundUnconnectedStatus = false;
                    // status is the matching status to the first element of the list (see above)
                    List<Status> outGoing = status.getOutGoing();
                    if (!sortedList.isEmpty()) { // there are histories
                        if (sortedList.size() > 1) { // there is more than one history which need to be checked first
                            // now iterate through the sorted list and check that all status are 'connected' properly
                            for (int i = 1; i < sortedList.size(); i++) { // skip first element; was done already
                                SortableHistory history = sortedList.get(i);
                                boolean foundCorrectStatusInIteration = false;

                                for (Status status1 : outGoing) { // check all outgoing edges of the previous entry
                                    String serviceStatus = history.getServiceStatus();
                                    if (serviceStatus.equals(status1.getName())) {
                                        outGoing = status1.getOutGoing();
                                        foundCorrectStatusInIteration = true;
                                    }
                                }
                                if (!foundCorrectStatusInIteration) {
                                    foundUnconnectedStatus = true;
                                    reference = history.getHistory();
                                }
                            }
                        }
                        if (!foundUnconnectedStatus) {
                            // compare the latest set of outGoing edges with the status of the service
                            boolean foundCorrectStatusInIteration = false;
                            for (Status status1 : outGoing) {
                                String serviceStatus = serviceInfo.getServiceStatus();
                                if (serviceStatus.equals(status1.getName())) {
                                    outGoing = status1.getOutGoing();
                                    foundCorrectStatusInIteration = true;
                                }
                            }
                            if (!foundCorrectStatusInIteration) {
                                foundUnconnectedStatus = true;
                                reference = service;
                            }
                        }
                        if (foundUnconnectedStatus) {
                            logger.error(
                                    uiKeys.getString("Validation.rule.serviceCurrentStatus.notConnectedCorrectly"),
                                    reference);
                        }
                    }
                }
            }
        }
    }

    /**
     * 5.5.4 Service current status
     Presence: This field shall be present.
     Description: It specifies the identifier of the current status of the service.
     Format: An identifier expressed as an URI.
     Value:  In the context of EU Member States,
     to the exception of the "NationalRootCA-QC" service type, the identifier of the status of all
     the services shall be one of the following URIs as defined in clause D.5:
     - Under Supervision:
     "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision"
     - Supervision of Service in Cessation:
     "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation"
     - Supervision Ceased:
     "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased"
     - Supervision Revoked:
     "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked"
     - Accredited:
     "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited"
     - Accreditation Ceased:
     "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased"
     - Accreditation Revoked:
     "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked"
     with regards to the "NationalRootCA-QC" service type (as defined in clause 5.5.1), the
     identifier of the status of such services shall be one of the following URIs as defined in
     clause D.5:
     - Set by national law:
     "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw"
     - Deprecated by national law:
     "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedbynationallaw"
     */
    void checkRuleTspServiceCurrentStatus() {
        final QName name = QNames._ServiceStatus_QNAME;
        final String schemeTerritory = tsl.getSchemeInformation().getSchemeTerritory();
        if (Configuration.getInstance().getCountryCodes().isCodeInList(schemeTerritory)) {
            // In EU
            if (services != null) {
                final String nationalRootCaQc = "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC";
                final String setByNationalLaw = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw";
                final String deprecatedByNationalLaw = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedbynationallaw";
                final List<String> allowedForNationalRootCAQC = new ArrayList<String>();
                allowedForNationalRootCAQC.add(setByNationalLaw);
                allowedForNationalRootCAQC.add(deprecatedByNationalLaw);

                final List<String> tslServiceStatuses = Arrays
                      .asList(Configuration.getInstance().getTL().getTslServiceStatus());
                tslServiceStatuses.removeAll(allowedForNationalRootCAQC);
                for (TSPServiceType service : services) {
                    TSPServiceInformationType serviceInfo = service.getServiceInformation();
                    final String serviceStatus = serviceInfo.getServiceStatus();
                    final String serviceTypeIdentifier = serviceInfo.getServiceTypeIdentifier();
                    if (!nationalRootCaQc.equals(serviceTypeIdentifier)) {
                        if (!tslServiceStatuses.contains(serviceStatus)) {
                            logger.error(name + uiKeys.getString("Validation.rule.serviceCurrentStatus.notAllowed"), service);
                        }
                    } else {
                        if (!allowedForNationalRootCAQC.contains(serviceStatus)) {
                            logger.error(name + uiKeys.getString("Validation.rule.serviceCurrentStatus.notAllowed"), service);
                        }
                    }
                }
            }
        }
    }

    /**
     * 5.5.8 TSP service definition URI
     * Presence: When the service type (clause 5.5.1) is "NationalRootCA-QC", this field shall be present. In other
     * cases, this field is optional.
     * Description: It specifies the URI(s) where relying parties can obtain service-specific information provided by
     * the TSP.
     * Format: A sequence of multilingual pointers (see clause 5.1.4).
     * Value: The referenced URI(s) shall provide a path to information describing the service as specified by
     * the TSP.
     * When the service type (clause 5.5.1) is "NationalRootCA-QC", this field shall specify the URI(s)
     * where relying parties can obtain service-specific information provided by the TSP including
     * details on the establishment and management rules of such services and relevant national
     * legislation where rules for national root scheme exist in legislation.
     */
    void checkRuleTspServiceDefinitionUrl() {
        final String name = QNames._TSPServiceDefinitionURI;
        if (services != null) {
            final String nationalRootCaQc = "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC";
            for (TSPServiceType service : services) {
                final String serviceTypeIdentifier = service.getServiceInformation().getServiceTypeIdentifier();
                if (nationalRootCaQc.equals(serviceTypeIdentifier)) {
                    final NonEmptyMultiLangURIListType schemeServiceDefinitionURI = service.getServiceInformation()
                          .getTSPServiceDefinitionURI();
                    boolean fieldPresent = true;
                    if (schemeServiceDefinitionURI == null) {
                        fieldPresent = false;
                    } else {
                        final List<NonEmptyMultiLangURIType> uriList = schemeServiceDefinitionURI.getURI();
                        if (uriList == null || uriList.isEmpty()) {
                            fieldPresent = false;
                        }
                    }

                    if (!fieldPresent) {
                        logger.error(name + uiKeys.getString("Validation.rule.tl.tsp.servicedefinitionuri"), service);
                    }
                }
            }
        }
    }

    private void applicabilityQualificationExtensionHelper(ExtensionsListType sie, String parent) {
        if (sie != null) {
            // all qualification extensions
            List<ExtensionType> qext = Util.extractMatching(sie, QNames._Qualifications_QNAME.getLocalPart(), false);
            for (ExtensionType extensionType : qext) {
                JAXBElement<?> element = Util.extractJAXBElement(extensionType);
                QualificationsType qt = (QualificationsType) element.getValue();
                for (QualificationElementType qelement : qt.getQualificationElement()) {
                    logger.error(uiKeys.getString("Validation.rule.qualificationExtensionApplicability.wrongType")
                            + parent + " is 'CA/QC'!", qelement);
                }
            }
        }
    }

    /**
     * QualificationExtension <p> The QualificationExtension can be used only if the Service TypeIdentifier = CA/QC.
     */
    private void checkRuleQualificationExtensionApplicability() {
        if (services != null) {
            String caqc = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
            for (TSPServiceType service : services) {
                ServiceHistoryType serviceHistory = service.getServiceHistory();
                if (serviceHistory != null) {
                    List<ServiceHistoryInstanceType> serviceHistoryInstance = serviceHistory
                            .getServiceHistoryInstance();
                    for (ServiceHistoryInstanceType history : serviceHistoryInstance) {
                        if (caqc.equals(history.getServiceTypeIdentifier())) {
                            continue; // this is fine, there can be a qualification extension below it
                        }
                        applicabilityQualificationExtensionHelper(
                                history.getServiceInformationExtensions(),
                                uiKeys.getString("Validation.rule.qualificationExtensionApplicability.reference.history"));
                    }
                }
                if (caqc.equals(service.getServiceInformation().getServiceTypeIdentifier())) {
                    continue;
                }
                applicabilityQualificationExtensionHelper(service.getServiceInformation()
                        .getServiceInformationExtensions(),
                        uiKeys.getString("Validation.rule.qualificationExtensionApplicability.reference.service"));
            }
        }
    }

    private void additionalServiceInformationExtensionHelper(ExtensionsListType sie, String sti) {
        // check disabled because the AdditionalServiceInformationType.uri has only one predefined value now (RootCA-QC)
        if (false && sie != null) {
            // all additional service information extensions
            List<ExtensionType> asiExt = Util.extractMatching(sie,
                    QNames._AdditionalServiceInformation_QNAME.getLocalPart(), false);
            for (ExtensionType extensionType : asiExt) {
                JAXBElement<?> element = Util.extractJAXBElement(extensionType);
                AdditionalServiceInformationType asi = (AdditionalServiceInformationType) element.getValue();
                String uri = asi.getURI().getValue();
                // although everything else is parameterized, this is a 'specific'
                // rule to check which justifies usage of hardcoded values here
                boolean ok = false;
                boolean uriIsToBeChecked = false;
                if (uri != null) {
                    if (uri.contains("OCSP-QC")) {
                        uriIsToBeChecked = true;
                        if (sti.contains("OCSP")) {
                            ok = true;
                        }
                    } else if (uri.contains("CRL-QC")) {
                        uriIsToBeChecked = true;
                        if (sti.contains("CRL")) {
                            ok = true;
                        }
                    } else if (uri.contains("RootCA-QC")) {
                        uriIsToBeChecked = true;
                        if (sti.contains("CA/QC")) {
                            ok = true;
                        }
                    } else if (uri.contains("TSS-QC")) {
                        uriIsToBeChecked = true;
                        if (sti.contains("TSA")) {
                            ok = true;
                        }
                    }
                }
                if (uriIsToBeChecked && !ok) {
                    logger.error(uiKeys.getString("Validation.rule.additionalServiceInformationExtension"), sie);
                }
            }
        }
    }

    /**
     * AdditionalServiceInformation <p> The available URIs are described in Trusted list configuration file. In addition,
     * the URI must respect the following association: URI = "OCSP-QC" only if Service TypeIdentifier = OCSP; URI =
     * "CRL-QC" only if Service TypeIdentifier = CRL; URI = "RootCA-QC" only if Service TypeIdentifier = CA/QC; URI =
     * "TSS-QC" only if Service TypeIdentifier = TSA;
     */
    private void checkRuleAdditionalServiceInformationExtension() {
        if (services != null) {
            for (TSPServiceType service : services) {
                ServiceHistoryType serviceHistory = service.getServiceHistory();
                if (serviceHistory != null) {
                    List<ServiceHistoryInstanceType> serviceHistoryInstance = serviceHistory
                            .getServiceHistoryInstance();
                    for (ServiceHistoryInstanceType history : serviceHistoryInstance) {
                        additionalServiceInformationExtensionHelper(history.getServiceInformationExtensions(),
                                history.getServiceTypeIdentifier());
                    }
                }
                TSPServiceInformationType sinfo = service.getServiceInformation();
                additionalServiceInformationExtensionHelper(sinfo.getServiceInformationExtensions(),
                        sinfo.getServiceTypeIdentifier());
            }
        }
    }

    /**
     * ExpiredCertsRevocationExtension <p> The critical attribute must be set to "False".
     */
    private void checkRuleExpiredCertsRevocationExtensionCriticality() {
        if (extensions != null) {
            for (ExtensionsListType extension : extensions) {
                List<ExtensionType> ecriExt = Util.extractMatching(extension,
                        QNames._ExpiredCertsRevocationInfo_QNAME.getLocalPart(), false);
                for (ExtensionType extensionType : ecriExt) {
                    if (extensionType.isCritical()) {
                        logger.error(uiKeys.getString("Validation.rule.expiredCertsRevocationExtensionCriticality"),
                                extension);
                    }
                }
            }
        }
    }

    private void expiredCertsRevocationExtensionApplicabilityHelper(ExtensionsListType sie, String sti) {
        if (sie != null) {
            // all expired certificates revocation information extensions
            List<ExtensionType> ecriExt = Util.extractMatching(sie,
                    QNames._ExpiredCertsRevocationInfo_QNAME.getLocalPart(), false);
            for (ExtensionType extensionType : ecriExt) {
                JAXBElement<?> element = Util.extractJAXBElement(extensionType);
                if (element.getValue() != null) {
                    boolean ok = false;
                    if (sti.contains("CA/PKC") || sti.contains("CA/QC") || sti.contains("OCSP")
                            || sti.contains("CRL")) {
                        ok = true;
                    }
                    if (!ok) {
                        logger.error(
                                uiKeys.getString("Validation.rule.ExpiredCertsRevocationExtensionApplicability"),
                                sie);
                    }
                }
            }
        }
    }

    /**
     * ExpiredCertsRevocationExtension <p> The "expiredCertsRevocationInfo" extension can be applied only to the following
     * service types: CA (PKC); CA (QC); Certificate status (OCSP); Certificate status (CRL).
     */
    private void checkRuleExpiredCertsRevocationExtensionApplicability() {
        if (services != null) {
            for (TSPServiceType service : services) {
                ServiceHistoryType serviceHistory = service.getServiceHistory();
                if (serviceHistory != null) {
                    List<ServiceHistoryInstanceType> serviceHistoryInstance = serviceHistory
                            .getServiceHistoryInstance();
                    for (ServiceHistoryInstanceType history : serviceHistoryInstance) {
                        expiredCertsRevocationExtensionApplicabilityHelper(
                                history.getServiceInformationExtensions(), history.getServiceTypeIdentifier());
                    }
                }
                TSPServiceInformationType sinfo = service.getServiceInformation();
                expiredCertsRevocationExtensionApplicabilityHelper(sinfo.getServiceInformationExtensions(),
                        sinfo.getServiceTypeIdentifier());
            }
        }
    }

    /**
     * @return the logger
     */
    public ValidationLogger getLogger() {
        return logger;
    }

    /**
     * for junit testing
     * @param services
     */
    void setServices(List<TSPServiceType> services) {
        this.services = services;
    }
}