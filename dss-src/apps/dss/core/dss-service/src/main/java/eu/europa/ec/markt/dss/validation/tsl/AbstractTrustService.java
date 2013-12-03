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

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;

import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.EncodingException.MSG;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.validation.tsl.CompositeCriteriaList.Composition;
import eu.europa.ec.markt.tsl.jaxb.ecc.CriteriaListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageBitType;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageType;
import eu.europa.ec.markt.tsl.jaxb.ecc.PoliciesListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationElementType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationsType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifierType;
import eu.europa.ec.markt.tsl.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionType;
import eu.europa.ec.markt.tsl.jaxb.tslx.TakenOverByType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectIdentifierType;

/**
 * Service information from current status and TrustedList shares some common information.
 * 
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public abstract class AbstractTrustService {

	private static final Logger LOG = Logger.getLogger(AbstractTrustService.class.getName());

	private static final String TSL = "http://uri.etsi.org/02231/v2#";

	private static final String TSLX = "http://uri.etsi.org/02231/v2/additionaltypes#";

	private boolean wellSigned = false;

	abstract protected List<ExtensionType> getExtensions();

	abstract protected DigitalIdentityListType getServiceDigitalIdentity();

	/**
	 * 
	 * @return
	 */
	abstract public String getType();

	/**
	 * Return the status of the service
	 * 
	 * @return
	 */
	abstract public String getStatus();

	/**
	 * @return
	 */
	abstract public Date getStatusStartDate();

	/**
	 * @return
	 */
	abstract public Date getStatusEndDate();

	/**
	 * 
	 * @return
	 */
	abstract public String getServiceName();

	/**
	 * Return the current status for the service
	 * 
	 * @return
	 */
	abstract public CurrentTrustService getCurrentServiceInfo();

	/**
	 * Return the list of certificate representing the digital identity of this service.
	 * 
	 * @return
	 */
	public List<X509Certificate> getDigitalIdentity() {

		CertificateFactory factory;
		try {
			factory = CertificateFactory.getInstance("X509");
			List<X509Certificate> certs = new ArrayList<X509Certificate>();
			for (DigitalIdentityType id : getServiceDigitalIdentity().getDigitalId()) {
				try {
					if (id.getX509Certificate() != null) {
						certs.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(id.getX509Certificate())));
					} else {
						LOG.log(Level.FINE, "I don't know if it's important, but the ID is null");
					}

				} catch (CertificateException ex) {
					LOG.log(Level.WARNING, ex.getMessage());
				}

			}
			return certs;
		} catch (CertificateException ex) {
			Logger.getLogger(CurrentTrustService.class.getName()).log(Level.SEVERE, null, ex);
			throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
		}

	}

	/**
	 * 
	 * @return
	 */
	public ServiceInfo createServiceInfo() {

		ServiceInfo service = new ServiceInfo();

		List<QualificationsType> list = getQualificationsType();
		if (list.size() > 1) {
			LOG.warning("There is more than one QualificationsType in the service");
		}

		for (QualificationsType qual : list) {
			if (qual.getQualificationElement() != null) {
				for (QualificationElementType el : qual.getQualificationElement()) {
					parseQualificationElement(el, service);
				}
			}
		}

		return service;
	}

	@SuppressWarnings("rawtypes")
	private List<QualificationsType> getQualificationsType() {

		List<QualificationsType> qual = new ArrayList<QualificationsType>();

		for (ExtensionType ext : getExtensions()) {
			for (Object o : ext.getContent()) {
				if (o instanceof String) {
					/* Don't do anything */
					if (o.toString().trim().length() == 0) {
						LOG.fine("The extension contains only blank text ?!");
					} else {
						LOG.warning("Extension containing " + o.toString());
						throw new RuntimeException();
					}
				} else if (o instanceof JAXBElement) {
					JAXBElement e = (JAXBElement) o;
					if (e.getValue() instanceof AdditionalServiceInformationType) {
						// Do nothing
					} else if (e.getValue() instanceof QualificationsType) {
						qual.add((QualificationsType) e.getValue());
					} else if (e.getValue() instanceof TakenOverByType) {
						// Do nothing
					} else if (e.getValue() instanceof XMLGregorianCalendar) {
						// Do nothing
					} else {
						LOG.log(Level.WARNING, "Unrecognized extension class {0}", e.getValue().getClass());
					}
				} else if (o instanceof Element) {
					/* We don't know what to do with the Element without further analysis */
					Element e = (Element) o;
					if ("AdditionalServiceInformation".equals(e.getLocalName()) && TSLX.equals(e.getNamespaceURI())) {
						// Do nothing
					} else if ("TakenOverBy".equals(e.getLocalName()) && TSL.equals(e.getNamespaceURI())) {
						// Do nothing
					} else {
						throw new NotETSICompliantException(NotETSICompliantException.MSG.UNRECOGNIZED_TAG);
					}
				} else {
					throw new RuntimeException("Unknown extension " + o.getClass());
				}
			}
		}

		return qual;
	}

	private void parseQualificationElement(QualificationElementType el, ServiceInfo service) {

		List<String> qualifiersString = new ArrayList<String>();

		if (el.getQualifiers() != null) {
			for (QualifierType qt : el.getQualifiers().getQualifier()) {
				qualifiersString.add(qt.getUri());
			}
			if (el.getCriteriaList() != null) {
				CriteriaListType criteria = el.getCriteriaList();

				if (criteria.getKeyUsage().isEmpty() && criteria.getPolicySet().isEmpty()) {
					LOG.fine("CriteriaList for service is empty, we skip the QualificationElement");
					return;
				}

				String assertValue = el.getCriteriaList().getAssert();
				if (!"all".equals(assertValue) && !"atLeastOne".equals(assertValue) && !"none".equals(assertValue)) {
					throw new NotETSICompliantException(NotETSICompliantException.MSG.UNSUPPORTED_ASSERT);
				}
				LOG.fine(assertValue);

				if (!criteria.getCriteriaList().isEmpty()) {
					LOG.severe("No support for nested CriteriaList");
				}

				Condition composite = parseCriteriaList(criteria, assertValue);
				for (String qualifier : qualifiersString) {
					service.addQualifier(qualifier, composite);
				}
			}

		}

	}

	private Condition parseCriteriaList(CriteriaListType criteria, String assertValue) {

		List<Condition> conditions = new ArrayList<Condition>();

		for (PoliciesListType p : criteria.getPolicySet()) {
			for (ObjectIdentifierType t : p.getPolicyIdentifier()) {
				if (t.getIdentifier().getQualifier() == null) {
					conditions.add(new PolicyIdCondition(t.getIdentifier().getValue()));
				} else {
					String id = t.getIdentifier().getValue();
					if (id.indexOf(':') >= 0) {
						id = id.substring(id.lastIndexOf(':') + 1);
					}
					conditions.add(new PolicyIdCondition(id));
				}
			}
		}

		for (KeyUsageType t : criteria.getKeyUsage()) {
			for (KeyUsageBitType b : t.getKeyUsageBit()) {
				conditions.add(new KeyUsageCondition(b.getName()));
			}
		}

		Condition composite = new CompositeCriteriaList(Composition.valueOf(assertValue), conditions);
		return composite;
	}

	/**
	 * @return the wellSigned
	 */
	public boolean isWellSigned() {

		return wellSigned;
	}

	/**
	 * @param wellSigned the wellSigned to set
	 */
	public void setWellSigned(boolean wellSigned) {

		this.wellSigned = wellSigned;
	}

}
