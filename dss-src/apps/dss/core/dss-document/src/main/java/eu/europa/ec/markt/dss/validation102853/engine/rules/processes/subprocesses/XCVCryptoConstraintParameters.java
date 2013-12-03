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

package eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses;

import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters;

public class XCVCryptoConstraintParameters extends ProcessParameters {

   private String contextName;

   private XmlDom certificate;

   public XCVCryptoConstraintParameters(ProcessParameters params) {

      currentTime = params.getCurrentTime();
      constraintData = params.getConstraintData();
      contextName = params.getContextName();
   }

   @Override
   public String getContextName() {
      return contextName;
   }

   @Override
   public void setContextName(String contextName) {
      this.contextName = contextName;
   }

   public XmlDom getCertificate() {
      return certificate;
   }

   public void setCertificate(XmlDom certificate) {
      this.certificate = certificate;
   }

}
