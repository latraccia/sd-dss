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

package eu.europa.ec.markt.dss.signature.cades;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.SignatureParameters;

/**
 * This class holds the CAdES-BES signature profile; it supports the inclusion of the mandatory signed
 * id_aa_signingCertificate[V2] attribute as specified in ETSI TS 101 733 V1.8.1, clause 5.7.3.
 * 
 * 
 * @version $Revision: 1817 $ - $Date: 2013-03-28 15:54:49 +0100 (jeu., 28 mars 2013) $
 */

public class CAdESProfileBES {

    private boolean padesUsage;

    /**
     * The default constructor for CAdESProfileBES.
     */
    public CAdESProfileBES() {
        this(false);
    }

    /**
     * The default constructor for CAdESProfileBES.
     */
    public CAdESProfileBES(boolean padesUsage) {
       
   	 this.padesUsage = padesUsage;
    }

    private Attribute makeSigningCertificateAttribute(SignatureParameters parameters) {
       
   	 try {
            MessageDigest dig = MessageDigest.getInstance(parameters.getDigestAlgorithm().getName(), new BouncyCastleProvider());
            byte[] certHash = dig.digest(parameters.getSigningCertificate().getEncoded());

            if (parameters.getDigestAlgorithm() == DigestAlgorithm.SHA1) {
                SigningCertificate sc = new SigningCertificate(new ESSCertID(certHash));

                return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, new DERSet(sc));

            } else {
                ESSCertIDv2 essCert = new ESSCertIDv2(new AlgorithmIdentifier(parameters.getDigestAlgorithm().getOid()), certHash);
                SigningCertificateV2 scv2 = new SigningCertificateV2(new ESSCertIDv2[] { essCert });

                return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(scv2));
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

    }

    private Attribute makeSigningTimeAttribute(SignatureParameters parameters) {
        return new Attribute(PKCSObjectIdentifiers.pkcs_9_at_signingTime, new DERSet(new Time(parameters.getSigningDate())));
    }

    private Attribute makeSignerAttrAttribute(SignatureParameters parameters) {
        DEROctetString[] roles = new DEROctetString[1];
        roles[0] = new DEROctetString(parameters.getClaimedSignerRole().getBytes());
        return new Attribute(PKCSObjectIdentifiers.id_aa_ets_signerAttr, new DERSet(new SignerAttribute(new DERSequence(roles))));

    }

    Hashtable<ASN1ObjectIdentifier, ASN1Encodable> getSignedAttributes(SignatureParameters parameters) {
        Hashtable<ASN1ObjectIdentifier, ASN1Encodable> signedAttrs = new Hashtable<ASN1ObjectIdentifier, ASN1Encodable>();
        Attribute signingCertificateReference = makeSigningCertificateAttribute(parameters);
        signedAttrs.put((ASN1ObjectIdentifier) signingCertificateReference.getAttrType(), signingCertificateReference);

        /*
         * In PAdES, we don't include the signing time : ETSI TS 102 778-3 V1.2.1 (2010-07): 4.5.3 signing-time
         * Attribute
         */
        if (!padesUsage) {
            signedAttrs.put(PKCSObjectIdentifiers.pkcs_9_at_signingTime, makeSigningTimeAttribute(parameters));
        }

        /*
         * In PAdES, the role is in the signature dictionary
         */
        if (!padesUsage && parameters.getClaimedSignerRole() != null) {
            signedAttrs.put(PKCSObjectIdentifiers.id_aa_ets_signerAttr, makeSignerAttrAttribute(parameters));
        }
        return signedAttrs;
    }

    /**
     * Return the table of unsigned properties.
     * 
     * @param parameters
     * @return
     */
    public Hashtable<ASN1ObjectIdentifier, ASN1Encodable> getUnsignedAttributes(SignatureParameters parameters) {
        return new Hashtable<ASN1ObjectIdentifier, ASN1Encodable>();
    }

}
