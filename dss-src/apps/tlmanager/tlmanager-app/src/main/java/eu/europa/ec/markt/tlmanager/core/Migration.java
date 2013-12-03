package eu.europa.ec.markt.tlmanager.core;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationElementType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationsType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifierType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifiersType;
import eu.europa.ec.markt.tsl.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.AnyType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionsListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyURIListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.OtherTSLPointerType;
import eu.europa.ec.markt.tsl.jaxb.tsl.OtherTSLPointersType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceHistoryType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServiceInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServiceType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServicesListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustStatusListType;

/**
 * Convert the jaxbElement in the new version. Changes URI to the new ones when possible
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class Migration {

    public static final BigInteger TSL_VERSION_SOURCE = BigInteger.valueOf(3);
    public static final BigInteger TSL_VERSION_TARGET = BigInteger.valueOf(4);
    private final MigrationMessages migrationMessages = new MigrationMessages();
    private final TrustStatusListType tsl;

    public static class MigrationMessages {
        private final List<String> messges = new ArrayList<String>();

        public MigrationMessages addMessage(String message) {
            messges.add(message);
            return this;
        }

        public List<String> getMessges() {
            return Collections.unmodifiableList(messges);
        }

    }

    /**
     * Construtor for the migration
     *
     * @param jaxbElement the tsl document to be migrated
     */
    public Migration(JAXBElement<TrustStatusListType> jaxbElement) {
        this.tsl = jaxbElement.getValue();
    }

    /**
     * Migrates the current document to the new version. Document will be changed.
     */
    public void migrate() {
        updateTSLVersionIdentifier();
        updateTSLType();
        updateStatusDeterminationApproach();
        updateTSP();
        updatePointers();
        updateSchemeTypeCommunityRules();
    }

    private void updateSchemeTypeCommunityRules() {
        final TSLSchemeInformationType schemeInformation = tsl.getSchemeInformation();
        if (schemeInformation == null) {
            return;
        }
        final NonEmptyMultiLangURIListType schemeTypeCommunityRules = schemeInformation.getSchemeTypeCommunityRules();
        if (schemeTypeCommunityRules == null) {
            return;
        }
        final List<NonEmptyMultiLangURIType> uris = schemeTypeCommunityRules.getURI();
        if (uris == null) {
            return;
        }
        final List<NonEmptyMultiLangURIType> newUris = new ArrayList<NonEmptyMultiLangURIType>();
        for (final NonEmptyMultiLangURIType uri : uris) {
            NonEmptyMultiLangURIType newUri = uri;
            if (StringUtils
                  .equals(uri.getValue(), "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/schemerules/common")) {
                newUri.setValue("http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUcommon");
            } else {
                Pattern pattern = Pattern
                      .compile("^http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/schemerules/([A-Z][A-Z])$");
                final Matcher matcher = pattern.matcher(uri.getValue());
                if (matcher.matches()) {
                    String country = matcher.group(1);
                    newUri.setValue("http://uri.etsi.org/TrstSvc/TrustedList/schemerules/" + country);
                }
                if (StringUtils.equals(uri.getValue(),
                      "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/schemerules/CompiledList")) {
                    newUri.setValue("http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUlistofthelists");
                }
            }
            newUris.add(newUri);
        }
        schemeTypeCommunityRules.getURI().clear();
        schemeTypeCommunityRules.getURI().addAll(newUris);
    }

    private void updateTSLVersionIdentifier() {
        final TSLSchemeInformationType schemeInformation = tsl.getSchemeInformation();
        if (schemeInformation != null) {
            schemeInformation.setTSLVersionIdentifier(TSL_VERSION_TARGET);
        }
    }

    private void updateTSLType() {
        final TSLSchemeInformationType schemeInformation = tsl.getSchemeInformation();
        if (schemeInformation != null) {
            final String originalTslType = schemeInformation.getTSLType();
            String newTslType = Configuration.getInstance().getTSL().getTslType();
            if ("http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/generic".equals(originalTslType)) {
                newTslType = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";
            } else if ("http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/schemes"
                  .equals(originalTslType)) {
                newTslType = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";
            }
            schemeInformation.setTSLType(newTslType);
        }
    }

    private void updateStatusDeterminationApproach() {
        final TSLSchemeInformationType schemeInformation = tsl.getSchemeInformation();
        if (schemeInformation != null) {
            final String originalStatusDeterminationApproach = schemeInformation.getStatusDeterminationApproach();
            if ("http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/StatusDetn/appropriate".equals(
                  originalStatusDeterminationApproach) || "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/StatusDetn/list"
                  .equals(originalStatusDeterminationApproach)) {
                schemeInformation.setStatusDeterminationApproach(
                      "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/StatusDetn/EUappropriate");
            }
        }
    }

    private void updateTSP() {
        final TrustServiceProviderListType trustServiceProviderList = tsl.getTrustServiceProviderList();
        if (trustServiceProviderList == null) {
            return;
        }
        final List<TSPType> trustServiceProvider = trustServiceProviderList.getTrustServiceProvider();
        if (trustServiceProvider == null) {
            return;
        }
        for (TSPType tspType : trustServiceProvider) {
            final TSPServicesListType tspServices = tspType.getTSPServices();
            if (tspServices == null) {
                continue;
            }
            final List<TSPServiceType> tspService = tspServices.getTSPService();
            if (tspService == null) {
                continue;
            }
            for (TSPServiceType tspServiceType : tspService) {

                final TSPServiceInformationType serviceInformation = tspServiceType.getServiceInformation();
                if (serviceInformation != null) {
                    updateTspCurrentStatus(serviceInformation);
                    updateTspExtensions(serviceInformation);
                }

                updateTspServiceHistory(tspServiceType);
            }
        }
    }


    private void updateTspExtensions(TSPServiceInformationType serviceInformation) {
        // search for qualifiers
        final ExtensionsListType serviceInformationExtensions = serviceInformation.getServiceInformationExtensions();
        if (serviceInformationExtensions == null) {
            return;
        }
        final List<ExtensionType> extension = serviceInformationExtensions.getExtension();
        if (extension == null) {
            return;
        }
        for (ExtensionType extensionType : extension) {
            final List<Object> extensionContentList = extensionType.getContent();
            if (extensionContentList == null) {
                continue;
            }
            for (Object extensionContent : extensionContentList) {
                if (extensionContent instanceof JAXBElement) {
                    JAXBElement<?> element = (JAXBElement<?>) extensionContent;
                    final Object elementValue = element.getValue();
                    updateQualifiers(elementValue);
                    updateAdditionalInformationExtension(elementValue);

                }
            }
        }
    }

    private void updateAdditionalInformationExtension(Object elementValue) {
        if (elementValue instanceof AdditionalServiceInformationType) {
            final AdditionalServiceInformationType additionalServiceInformationType = (AdditionalServiceInformationType) elementValue;
            final NonEmptyMultiLangURIType uri = additionalServiceInformationType.getURI();
            if (uri != null) {
                final String uriValue = uri.getValue();
                final String newUriValue = uriValue.replaceAll("eSigDir-1999-93-EC-TrustedList", "TrustedList");
                uri.setValue(newUriValue);
            }
        }
    }

    private void updateQualifiers(Object elementValue) {
        if (elementValue instanceof QualificationsType) {
            final QualificationsType qualificationsType = (QualificationsType) elementValue;
            final List<QualificationElementType> qualificationElementList = qualificationsType
                  .getQualificationElement();
            if (qualificationElementList != null) {
                for (QualificationElementType qualificationElementType : qualificationElementList) {
                    final QualifiersType qualifiers = qualificationElementType.getQualifiers();
                    if (qualifiers != null) {
                        final List<QualifierType> qualifierList = qualifiers.getQualifier();
                        if (qualifierList != null) {
                            for (QualifierType qualifier : qualifierList) {
                                final String qualifierUri = qualifier.getUri();
                                final String newQualifierUri = qualifierUri
                                      .replaceAll("eSigDir-1999-93-EC-TrustedList", "TrustedList");
                                qualifier.setUri(newQualifierUri);
                            }
                        }
                    }
                }
            }
        }
    }

    private void updateTspCurrentStatus(TSPServiceInformationType serviceInformation) {
        final String serviceCurrentStatus = serviceInformation.getServiceStatus();
        final String newServiceCurrentStatus = serviceCurrentStatus
              .replaceAll("eSigDir-1999-93-EC-TrustedList", "TrustedList");
        serviceInformation.setServiceStatus(newServiceCurrentStatus);
    }

    private void updateTspServiceHistory(TSPServiceType tspServiceType) {
        final ServiceHistoryType serviceHistory = tspServiceType.getServiceHistory();
        if (serviceHistory == null) {
            return;
        }
        final List<ServiceHistoryInstanceType> serviceHistoryInstance = serviceHistory.getServiceHistoryInstance();
        if (serviceHistoryInstance == null) {
            return;
        }
        for (ServiceHistoryInstanceType serviceHistoryInstanceType : serviceHistoryInstance) {
            final String servicePastStatus = serviceHistoryInstanceType.getServiceStatus();
            final String newServicePastStatus = servicePastStatus
                  .replaceAll("eSigDir-1999-93-EC-TrustedList", "TrustedList");
            serviceHistoryInstanceType.setServiceStatus(newServicePastStatus);
        }
    }

    private void updatePointers() {
        final TSLSchemeInformationType schemeInformation = tsl.getSchemeInformation();
        if (schemeInformation == null) {
            return;
        }
        final OtherTSLPointersType pointersToOtherTSL = schemeInformation.getPointersToOtherTSL();
        if (pointersToOtherTSL == null) {
            return;
        }
        final List<OtherTSLPointerType> otherTSLPointer = pointersToOtherTSL.getOtherTSLPointer();
        if (otherTSLPointer == null) {
            return;
        }
        for (OtherTSLPointerType otherTSLPointerType : otherTSLPointer) {
            updateOtherTSLPointerType(otherTSLPointerType);
        }
    }

    private void updateOtherTSLPointerType(OtherTSLPointerType otherTSLPointerType) {
        final JAXBElement<String> originalTslType = getAdditionalDataNode(otherTSLPointerType, QNames._TSLType_QNAME);
        if (originalTslType == null) {
            return;
        }
        String newTslType = Configuration.getInstance().getTSL().getTslTypeInverse();
        if ("http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/generic"
              .equals(originalTslType.getValue())) {
            newTslType = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";
        } else if ("http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/schemes"
              .equals(originalTslType.getValue())) {
            newTslType = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";
        }
        originalTslType.setValue(newTslType);
    }

    private JAXBElement<String> getAdditionalDataNode(OtherTSLPointerType pointer, QName qname) {
        List<Serializable> textualInformationOrOtherInformation = pointer.getAdditionalInformation()
              .getTextualInformationOrOtherInformation();
        for (Object obj : textualInformationOrOtherInformation) {
            if (obj instanceof AnyType) {
                AnyType anyType = (AnyType) obj;
                List<Object> content = anyType.getContent();
                JAXBElement<Object> element = null;
                if (content.isEmpty()) {
                    continue;
                }
                Object object = content.get(0);
                if (object != null && object instanceof JAXBElement<?>) {
                    element = (JAXBElement<Object>) object;
                }
                if (element != null && object != null) {
                    if (element.getName().getLocalPart().equals(qname.getLocalPart())) {
                        return (JAXBElement<String>) object;
                    }
                }
            }
        }
        return null;
    }

    public MigrationMessages getMigrationMessages() {
        return migrationMessages;
    }

}
