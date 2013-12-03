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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlType;

import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.report.Result.ResultStatus;

/**
 * Information for all the levels of the signature.
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureLevelAnalysis {

    @XmlTransient
    private AdvancedSignature signature;
    @XmlElement
    private SignatureLevelBES levelBES;
    @XmlElement
    private SignatureLevelEPES levelEPES;
    @XmlElement
    private SignatureLevelT levelT;
    @XmlElement
    private SignatureLevelC levelC;
    @XmlElement
    private SignatureLevelX levelX;
    @XmlElement
    private SignatureLevelXL levelXL;
    @XmlElement
    private SignatureLevelA levelA;
    @XmlElement
    private SignatureLevelLTV levelLTV;

    @XmlTransient
    private SignatureLevel lastLevelReached;

    public SignatureLevelAnalysis() {
    }

    /**
     * The default constructor for SignatureLevelAnalysis.
     * 
     * @param name
     * @param signature
     */
    public SignatureLevelAnalysis(AdvancedSignature signature, SignatureLevelBES levelBES, SignatureLevelEPES levelEPES, SignatureLevelT levelT,
            SignatureLevelC levelC, SignatureLevelX levelX, SignatureLevelXL levelXL, SignatureLevelA levelA, SignatureLevelLTV levelLTV) {
        this.signature = signature;

        this.levelBES = levelBES;
        this.levelEPES = levelEPES;
        this.levelT = levelT;
        this.levelC = levelC;
        this.levelX = levelX;
        this.levelXL = levelXL;
        this.levelA = levelA;
        this.levelLTV = levelLTV;

        processLastLevelReached();
    }

    private void processLastLevelReached() {

        // these are the "... requires ..."
        // EPES if BES
        // LTV if BES
        // A if XL if X if C if T if BES

        // check the dependencies (and invalidate if not reached)
        final boolean reachedBES = checkLevelReached(levelBES, true);
        final boolean reachedEPES = checkLevelReached(levelEPES, reachedBES);
        final boolean reachedT = checkLevelReached(levelT, reachedBES);
        final boolean reachedC = checkLevelReached(levelC, reachedT);
        final boolean reachedX = checkLevelReached(levelX, reachedC);
        final boolean reachedXL = checkLevelReached(levelXL, reachedX);
        final boolean reachedA = checkLevelReached(levelA, reachedXL);
        final boolean reachedLTV = checkLevelReached(levelLTV, reachedBES);

        lastLevelReached = null;
        lastLevelReached = reachedBES ? levelBES : lastLevelReached;
        lastLevelReached = reachedEPES ? levelEPES : lastLevelReached;
        lastLevelReached = reachedT ? levelT : lastLevelReached;
        lastLevelReached = reachedC ? levelC : lastLevelReached;
        lastLevelReached = reachedX ? levelX : lastLevelReached;
        lastLevelReached = reachedXL ? levelXL : lastLevelReached;
        lastLevelReached = reachedA ? levelA : lastLevelReached;
        lastLevelReached = reachedLTV ? levelLTV : lastLevelReached;

    }

    public SignatureLevel getLastLevelReached() {
        return lastLevelReached;
    }

    private boolean checkLevelReached(final SignatureLevel level, final boolean reachedPrevious) {
        if (level == null) {
            return false;
        }
        // invalidate if the previous required level is not reached
        if (!reachedPrevious) {
            level.getLevelReached().setStatus(ResultStatus.INVALID, "previous.level.has.errors");
        }
        return level.getLevelReached().isValid();
    }

    /**
     * @return the signatureFormat
     */
    public String getSignatureFormat() {
        final String name = SignatureLevel.toAcronym(signature);
        if (name != null) {
            return name;
        }
        throw new IllegalStateException("Unsupported AdvancedSignature " + signature.getClass().getName());
    }

    /**
     * @return the signature
     */
    public AdvancedSignature getSignature() {
        return signature;
    }

    /**
     * Get report for level BES
     * 
     * @return
     */
    public SignatureLevelBES getLevelBES() {
        return levelBES;
    }

    /**
     * Get report for level EPES
     * 
     * @return
     */
    public SignatureLevelEPES getLevelEPES() {
        return levelEPES;
    }

    /**
     * Get report for level T
     * 
     * @return
     */
    public SignatureLevelT getLevelT() {
        return levelT;
    }

    /**
     * Get report for level C
     * 
     * @return
     */
    public SignatureLevelC getLevelC() {
        return levelC;
    }

    /**
     * Get report for level X
     * 
     * @return
     */
    public SignatureLevelX getLevelX() {
        return levelX;
    }

    /**
     * Get report for level XL
     * 
     * @return
     */
    public SignatureLevelXL getLevelXL() {
        return levelXL;
    }

    /**
     * Get report for level A
     * 
     * @return
     */
    public SignatureLevelA getLevelA() {
        return levelA;
    }

    /**
     * Get report for level LTV
     * 
     * @return
     */
    public SignatureLevelLTV getLevelLTV() {
        return levelLTV;
    }

    public String toString(String indent) {
        StringBuilder s = new StringBuilder();

        s.append(indent).append("[SignatureLevelAnalysis\n");
        indent += "\t";

        s.append(indent).append("SignatureFormat: ").append(getSignatureFormat()).append("\n");
        AdvancedSignature as = getSignature();
        if ( as != null ) {
            s.append(indent).append("AdvancedSignature:").append("\n");
            s.append(indent).append("\t").append(as.getSignatureAlgorithm()).append("\n");
            s.append(indent).append("\t").append(as.getSigningTime()).append(" [TODO: to develop]\n");
        }
        if ( getLevelBES() != null ) {
            s.append(getLevelBES().toString(indent));
        }
        if ( getLevelEPES() != null ) {
            s.append(getLevelEPES().toString(indent));
        }
        if ( getLevelT() != null ) {
            s.append(getLevelT().toString(indent));
        }
        if (getLevelC() != null) {
            s.append(getLevelC().toString(indent));
        }
        if (getLevelX() != null) {
            s.append(getLevelX().toString(indent));
        }
        if (getLevelXL() != null) {
            s.append(getLevelXL().toString(indent));
        }
        if (getLevelA() != null) {
            s.append(getLevelA().toString(indent));
        }
        if (getLevelLTV() != null) {
            s.append(getLevelLTV().toString(indent));
        }

        indent = indent.substring(1);
        s.append(indent).append("]\n");

        return s.toString();
    }

    @Override
    public String toString() {
        return toString("");
    }

}
