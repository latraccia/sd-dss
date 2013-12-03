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
package eu.europa.ec.markt.dss.signature;

import eu.europa.ec.markt.dss.EncryptionAlgorithm;

import java.io.IOException;

/**
 * This is the utility class to manipulate different signature types.
 * 
 * @author bielecro
 * 
 */
public final class DSSSignatureUtils {

   /**
    * Converts the binary signature value to the Xml DSig format in function of used algorithm
    * 
    * @param algorithm Signature algorithm used to create the signatureValue
    * @param signatureValue
    * @return
    */
   public static byte[] convertToXmlDSig(final EncryptionAlgorithm algorithm, byte[] signatureValue) {

      try {

         if (algorithm == EncryptionAlgorithm.ECDSA) {

            return DSSSignatureUtils.convertECDSAASN1toXMLDSIG(signatureValue);
         } else if (algorithm == EncryptionAlgorithm.DSA) {

            return DSSSignatureUtils.convertDSAASN1toXMLDSIG(signatureValue);
         }
         return signatureValue;
      } catch (IOException e) {

         throw new RuntimeException(e);
      }
   }

   /**
    * Converts an ASN.1 DSA value to a XML Signature DSA Value.
    * 
    * The JAVA JCE DSA Signature algorithm creates ASN.1 encoded (r,s) value pairs; the XML Signature requires the core
    * BigInteger values.
    * 
    * @param asn1Bytes
    * @return the decode bytes
    * 
    * @throws IOException
    * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
    */
   public static byte[] convertDSAASN1toXMLDSIG(byte asn1Bytes[]) throws IOException {

      byte rLength = asn1Bytes[3];
      int ii;
      for (ii = rLength; (ii > 0) && (asn1Bytes[(4 + rLength) - ii] == 0); ii--)
         ;

      byte sLength = asn1Bytes[5 + rLength];
      int jj;
      for (jj = sLength; (jj > 0) && (asn1Bytes[(6 + rLength + sLength) - jj] == 0); jj--)
         ;

      if ((asn1Bytes[0] != 48) || (asn1Bytes[1] != asn1Bytes.length - 2) || (asn1Bytes[2] != 2) || (ii > 20) || (asn1Bytes[4 + rLength] != 2) || (jj > 20)) {

         throw new IOException("Invalid ASN.1 format of DSA signature");
      }
      byte xmldsigBytes[] = new byte[40];

      System.arraycopy(asn1Bytes, (4 + rLength) - ii, xmldsigBytes, 20 - ii, ii);
      System.arraycopy(asn1Bytes, (6 + rLength + sLength) - jj, xmldsigBytes, 40 - jj, jj);

      return xmldsigBytes;
   }

   /**
    * Converts an ASN.1 ECDSA value to a XML Signature ECDSA Value.
    * 
    * The JAVA JCE ECDSA Signature algorithm creates ASN.1 encoded (r,s) value pairs; the XML Signature requires the
    * core BigInteger values.
    * 
    * @param asn1Bytes
    * @return the decode bytes
    * 
    * @throws IOException
    * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
    * @see <A HREF="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</A>
    */
   public static byte[] convertECDSAASN1toXMLDSIG(byte asn1Bytes[]) throws IOException {

      if (asn1Bytes.length < 8 || asn1Bytes[0] != 48) {
         throw new IOException("Invalid ASN.1 format of ECDSA signature");
      }
      int offset;
      if (asn1Bytes[1] > 0) {
         offset = 2;
      } else if (asn1Bytes[1] == (byte) 0x81) {
         offset = 3;
      } else {
         throw new IOException("Invalid ASN.1 format of ECDSA signature");
      }

      byte rLength = asn1Bytes[offset + 1];
      int i;

      for (i = rLength; (i > 0) && (asn1Bytes[(offset + 2 + rLength) - i] == 0); i--)
         ;

      byte sLength = asn1Bytes[offset + 2 + rLength + 1];
      int j;

      for (j = sLength; (j > 0) && (asn1Bytes[(offset + 2 + rLength + 2 + sLength) - j] == 0); j--)
         ;

      int rawLen = Math.max(i, j);

      if ((asn1Bytes[offset - 1] & 0xff) != asn1Bytes.length - offset || (asn1Bytes[offset - 1] & 0xff) != 2 + rLength + 2 + sLength || asn1Bytes[offset] != 2 || asn1Bytes[offset + 2 + rLength] != 2) {
         throw new IOException("Invalid ASN.1 format of ECDSA signature");
      }
      byte xmldsigBytes[] = new byte[2 * rawLen];

      System.arraycopy(asn1Bytes, (offset + 2 + rLength) - i, xmldsigBytes, rawLen - i, i);
      System.arraycopy(asn1Bytes, (offset + 2 + rLength + 2 + sLength) - j, xmldsigBytes, 2 * rawLen - j, j);

      return xmldsigBytes;
   }
}
