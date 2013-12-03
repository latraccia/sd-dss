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

package eu.europa.ec.markt.dss.validation102853.tsl;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;

import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.EncodingException.MSG;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.validation102853.condition.CompositeCondition;
import eu.europa.ec.markt.dss.validation102853.condition.Condition;
import eu.europa.ec.markt.dss.validation102853.condition.CriteriaListCondition;
import eu.europa.ec.markt.dss.validation102853.condition.KeyUsageCondition;
import eu.europa.ec.markt.dss.validation102853.condition.MatchingCriteriaIndicator;
import eu.europa.ec.markt.dss.validation102853.condition.PolicyIdCondition;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.tsl.jaxb.ecc.CriteriaListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageBitType;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageType;
import eu.europa.ec.markt.tsl.jaxb.ecc.PoliciesListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationElementType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationsType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifierType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifiersType;
import eu.europa.ec.markt.tsl.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionType;
import eu.europa.ec.markt.tsl.jaxb.tslx.TakenOverByType;
import eu.europa.ec.markt.tsl.jaxb.xades.IdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectIdentifierType;

/**
 * Service information from current status and TrustedList shares some common information.
 *
 * @version $Revision: 1834 $ - $Date: 2013-03-28 16:04:04 +0100 (Thu, 28 Mar 2013) $
 */

abstract class AbstractTrustService {

    private static final Logger LOG = Logger.getLogger(AbstractTrustService.class.getName());

    private static final String TSL = "http://uri.etsi.org/02231/v2#";

    private static final String TSLX = "http://uri.etsi.org/02231/v2/additionaltypes#";

    private Date expiredCertsRevocationInfo;

    /**
     * @return
     */
    abstract List<ExtensionType> getExtensions();

    /**
     * @return
     */
    abstract DigitalIdentityListType getServiceDigitalIdentity();

    /**
     * @return
     */
    abstract String getType();

    /**
     * Return the status of the service
     *
     * @return
     */
    abstract String getStatus();

    /**
     * @return
     */
    abstract Date getStatusStartDate();

    /**
     * @return
     */
    abstract Date getStatusEndDate();

    /**
     * @return
     */
    abstract String getServiceName();

    /**
     * Return the list of certificate representing the digital identity of this service.
     *
     * @return
     */
    List<X509Certificate> getDigitalIdentity() {

        try {

            final List<X509Certificate> certs = new ArrayList<X509Certificate>();
            for (final DigitalIdentityType digitalIdentity : getServiceDigitalIdentity().getDigitalId()) {

                if (digitalIdentity.getX509Certificate() != null) {

                    final X509Certificate cert = DSSUtils.loadCertificate(digitalIdentity.getX509Certificate());
                    // System.out.println(" ----- > " + cert.getSubjectX500Principal());
                    certs.add(cert);
                } else {

                    LOG.log(Level.FINE, "I don't know if it's important, but the ID is null");
                }
            }
            return certs;
        } catch (DSSException e) {

            Logger.getLogger(CurrentTrustService.class.getName()).log(Level.SEVERE, e.getMessage(), e);
            throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ, e);
        }
    }

    /**
     * @return
     */
    ServiceInfo createServiceInfo() {

        ServiceInfo service = new ServiceInfo();
        List<QualificationsType> qualificationList = getQualificationsType();
        for (QualificationsType qualifications : qualificationList) {

            for (QualificationElementType qualificationElement : qualifications.getQualificationElement()) {

                parseQualificationElement(qualificationElement, service);
            }
        }

        service.setExpiredCertsRevocationInfo(expiredCertsRevocationInfo);

        return service;
    }

    @SuppressWarnings("rawtypes")
    private List<QualificationsType> getQualificationsType() {

        final List<QualificationsType> qualificationList = new ArrayList<QualificationsType>();
        for (final ExtensionType extension : getExtensions()) {

            for (final Object object : extension.getContent()) {

                if (object instanceof String) {

                    /* do nothing */
                    // if (StringUtils.isBlank(object.toString())) {
                    //
                    // } else {
                    //
                    //    LOG.warning("Extension containing " + object.toString());
                    //    throw new RuntimeException();
                    // }
                } else if (object instanceof JAXBElement) {

                    final JAXBElement jaxbElement = (JAXBElement) object;
                    final Object objectValue = jaxbElement.getValue();
                    if (objectValue instanceof AdditionalServiceInformationType) {

                        // Do nothing
                    } else if (objectValue instanceof QualificationsType) {

                        qualificationList.add((QualificationsType) jaxbElement.getValue());
                    } else if (objectValue instanceof TakenOverByType) {

                        // Do nothing
                    } else if (objectValue instanceof XMLGregorianCalendar) {

                        // {http://uri.etsi.org/02231/v2#}ExpiredCertsRevocationInfo
                        XMLGregorianCalendar xmlGregorianCalendar = (XMLGregorianCalendar) objectValue;
                        expiredCertsRevocationInfo = xmlGregorianCalendar.toGregorianCalendar().getTime();
                    } else {
                        LOG.log(Level.WARNING, "Unrecognized extension class {0}", jaxbElement.getValue().getClass());
                    }
                } else if (object instanceof Element) {

                    /* We don't know what to do with the Element without further analysis */
                    final Element element = (Element) object;
                    final String localName = element.getLocalName();
                    String namespaceUri = element.getNamespaceURI();
                    if ("AdditionalServiceInformation".equals(localName) && TSL.equals(namespaceUri)) {

                        // Do nothing
                    } else if ("TakenOverBy".equals(localName) && TSLX.equals(namespaceUri)) {

                        // Do nothing
                    } else {

                        if (TSLX.equals(namespaceUri)) {

                            namespaceUri = "TSLX";
                        } else if (TSL.equals(namespaceUri)) {

                            namespaceUri = "TSL";
                        }
                        throw new NotETSICompliantException(NotETSICompliantException.MSG.UNRECOGNIZED_TAG, namespaceUri + ":" + localName);
                    }
                } else {
                    throw new RuntimeException("Unknown extension " + object.getClass());
                }
            }
        }
        return qualificationList;
    }

    private void parseQualificationElement(final QualificationElementType qualificationElement, final ServiceInfo service) {

        final QualifiersType qualifierList = qualificationElement.getQualifiers();
        if (qualifierList == null || qualifierList.getQualifier().isEmpty()) {

            return;
        }
        try {

            final CriteriaListType criteriaList = qualificationElement.getCriteriaList();
            if (criteriaList != null) {

                if (criteriaList.getKeyUsage().isEmpty() && criteriaList.getPolicySet().isEmpty() && criteriaList.getCriteriaList().isEmpty()) {

                    LOG.fine("CriteriaList for service is empty, the QualificationElement is skipped.");
                    return;
                }
                final Condition compositeCondition = parseCriteriaList(criteriaList);
                for (QualifierType qualifier : qualifierList.getQualifier()) {

                    service.addQualifierAndCondition(qualifier.getUri(), compositeCondition);
                }
            }
        } catch (IllegalArgumentException e) {

            throw new NotETSICompliantException(NotETSICompliantException.MSG.UNSUPPORTED_ASSERT);
        }
    }

    private Condition parseCriteriaList(final CriteriaListType criteriaList) {

        final String assertValue = criteriaList.getAssert();
        if (assertValue == null) {

            System.out.println("null");
        }
        final MatchingCriteriaIndicator matchingCriteriaIndicator = MatchingCriteriaIndicator.valueOf(assertValue);

        final CompositeCondition condition = new CriteriaListCondition(matchingCriteriaIndicator);
        for (final PoliciesListType policies : criteriaList.getPolicySet()) {

            final CompositeCondition compositeCondition = new CompositeCondition();
            for (final ObjectIdentifierType objectIdentifier : policies.getPolicyIdentifier()) {

                final IdentifierType identifier = objectIdentifier.getIdentifier();
                if (identifier.getQualifier() == null) {

                    compositeCondition.addChild(new PolicyIdCondition(identifier.getValue()));
                } else {

                    String id = identifier.getValue();
                    if (id.indexOf(':') >= 0) {

                        id = id.substring(id.lastIndexOf(':') + 1);
                    }
                    compositeCondition.addChild(new PolicyIdCondition(id));
                }
            }
            condition.addChild(compositeCondition);
        }
        for (final KeyUsageType keyUsage : criteriaList.getKeyUsage()) {

            final CompositeCondition compositeCondition = new CompositeCondition();
            for (final KeyUsageBitType keyUsageBit : keyUsage.getKeyUsageBit()) {

                compositeCondition.addChild(new KeyUsageCondition(keyUsageBit.getName(), keyUsageBit.isValue()));
            }
            condition.addChild(compositeCondition);
        }
        for (final CriteriaListType criteria : criteriaList.getCriteriaList()) {

            final Condition compositeCondition = parseCriteriaList(criteria);
            condition.addChild(compositeCondition);
        }
        return condition;
    }
}
