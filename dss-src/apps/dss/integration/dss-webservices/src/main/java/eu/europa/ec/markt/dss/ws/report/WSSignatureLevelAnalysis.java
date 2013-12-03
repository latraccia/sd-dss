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

import eu.europa.ec.markt.dss.validation.report.SignatureLevelAnalysis;

/**
 * Wrap data of a SignatureLevelAnalysis. Used to expose the information in the Webservice.
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSSignatureLevelAnalysis {

    private WSSignatureLevelBES levelBES;

    private WSSignatureLevelEPES levelEPES;

    private WSSignatureLevelT levelT;

    private WSSignatureLevelC levelC;

    private WSSignatureLevelX levelX;

    private WSSignatureLevelXL levelXL;

    private WSSignatureLevelA levelA;

    private WSSignatureLevelLTV levelLTV;

    private String signatureFormat;

    /**
     * The default constructor for WSSignatureLevelAnalysis.
     */
    public WSSignatureLevelAnalysis() {
    }

    /**
     * 
     * The default constructor for WSSignatureLevelAnalysis.
     * 
     * @param analysis
     */
    public WSSignatureLevelAnalysis(SignatureLevelAnalysis analysis) {
        signatureFormat = analysis.getSignatureFormat();
        if (analysis.getLevelBES() != null) {
            levelBES = new WSSignatureLevelBES(analysis.getLevelBES());
        }
        if (analysis.getLevelEPES() != null) {
            levelEPES = new WSSignatureLevelEPES(analysis.getLevelEPES());
        }
        if (analysis.getLevelT() != null) {
            levelT = new WSSignatureLevelT(analysis.getLevelT());
        }
        if (analysis.getLevelC() != null) {
            levelC = new WSSignatureLevelC(analysis.getLevelC());
        }
        if (analysis.getLevelX() != null) {
            levelX = new WSSignatureLevelX(analysis.getLevelX());
        }
        if (analysis.getLevelA() != null) {
            levelA = new WSSignatureLevelA(analysis.getLevelA());
        }
        if (analysis.getLevelLTV() != null) {
            levelLTV = new WSSignatureLevelLTV(analysis.getLevelLTV());
        }
    }

    /**
     * @return the levelBES
     */
    public WSSignatureLevelBES getLevelBES() {
        return levelBES;
    }

    /**
     * @param levelBES the levelBES to set
     */
    public void setLevelBES(WSSignatureLevelBES levelBES) {
        this.levelBES = levelBES;
    }

    /**
     * @return the levelEPES
     */
    public WSSignatureLevelEPES getLevelEPES() {
        return levelEPES;
    }

    /**
     * @param levelEPES the levelEPES to set
     */
    public void setLevelEPES(WSSignatureLevelEPES levelEPES) {
        this.levelEPES = levelEPES;
    }

    /**
     * @return the levelT
     */
    public WSSignatureLevelT getLevelT() {
        return levelT;
    }

    /**
     * @param levelT the levelT to set
     */
    public void setLevelT(WSSignatureLevelT levelT) {
        this.levelT = levelT;
    }

    /**
     * @return the levelC
     */
    public WSSignatureLevelC getLevelC() {
        return levelC;
    }

    /**
     * @param levelC the levelC to set
     */
    public void setLevelC(WSSignatureLevelC levelC) {
        this.levelC = levelC;
    }

    /**
     * @return the levelX
     */
    public WSSignatureLevelX getLevelX() {
        return levelX;
    }

    /**
     * @param levelX the levelX to set
     */
    public void setLevelX(WSSignatureLevelX levelX) {
        this.levelX = levelX;
    }

    /**
     * @return the levelXL
     */
    public WSSignatureLevelXL getLevelXL() {
        return levelXL;
    }

    /**
     * @param levelXL the levelXL to set
     */
    public void setLevelXL(WSSignatureLevelXL levelXL) {
        this.levelXL = levelXL;
    }

    /**
     * @return the levelA
     */
    public WSSignatureLevelA getLevelA() {
        return levelA;
    }

    /**
     * @param levelA the levelA to set
     */
    public void setLevelA(WSSignatureLevelA levelA) {
        this.levelA = levelA;
    }

    /**
     * @return the levelLTV
     */
    public WSSignatureLevelLTV getLevelLTV() {
        return levelLTV;
    }

    /**
     * @param levelLTV the levelLTV to set
     */
    public void setLevelLTV(WSSignatureLevelLTV levelLTV) {
        this.levelLTV = levelLTV;
    }

    /**
     * @return the signatureFormat
     */
    public String getSignatureFormat() {
        return signatureFormat;
    }

    /**
     * @param signatureFormat the signatureFormat to set
     */
    public void setSignatureFormat(String signatureFormat) {
        this.signatureFormat = signatureFormat;
    }

}
