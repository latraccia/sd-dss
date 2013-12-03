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

package eu.europa.ec.markt.dss.signature.provider;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Custom Signature implementation that intercept the digest generation.
 * 
 * 
 * @version $Revision: 987 $ - $Date: 2011-06-16 15:51:38 +0200 (jeu., 16 juin 2011) $
 */

public class SignatureInterceptor extends Signature {

    private MessageDigest digester;

    private SpecialPrivateKey specialPrivateKey;

    /**
     * The default constructor for SignatureInterceptor.
     */
    public SignatureInterceptor() throws NoSuchAlgorithmException {
        super("SHA1withRSA");
        digester = MessageDigest.getInstance("SHA1");
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof SpecialPrivateKey) {
            specialPrivateKey = (SpecialPrivateKey) privateKey;
        } else {
            throw new IllegalArgumentException("Can only use instance of SpecialPrivateKey");
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        digester.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        digester.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        specialPrivateKey.setMessageDigest(digester.digest());
        byte[] signature = specialPrivateKey.getPreviouslyComputedSignature();
        if (signature == null) {
            return new byte[0];
        } else {
            return signature;
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

}
