package io.github.techynature.nestsigner.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/** Builds a self-signed X.509 v3 certificate (SHA256withRSA) without third-party libraries. */
final class CertBuilder {

    private static final String SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
    private static final String OID_SUBJECT_KEY_ID = "2.5.29.14";

    private CertBuilder() {}

    static X509Certificate build(KeyPair kp, CertInfo info, Date notBefore, Date notAfter,
                                 SecureRandom rnd) throws GeneralSecurityException {
        BigInteger serial = new BigInteger(63, rnd).add(BigInteger.ONE);
        byte[] sigAlg = Der.seq(Der.oid(SHA256_WITH_RSA), Der.nul());
        byte[] name = encodeName(info);
        byte[] spki = kp.getPublic().getEncoded(); // already a SubjectPublicKeyInfo

        // Subject Key Identifier, same as keytool adds (SHA-1 of the public key bits)
        byte[] keyId = MessageDigest.getInstance("SHA-1").digest(publicKeyBits(spki));
        byte[] skiExt = Der.seq(Der.oid(OID_SUBJECT_KEY_ID), Der.octetString(Der.octetString(keyId)));
        byte[] extensions = Der.explicit(3, Der.seq(skiExt));

        byte[] tbs = Der.seq(
                Der.explicit(0, Der.integer(BigInteger.valueOf(2))), // v3
                Der.integer(serial),
                sigAlg,
                name,
                Der.seq(Der.time(notBefore), Der.time(notAfter)),
                name,
                spki,
                extensions);

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(kp.getPrivate(), rnd);
        s.update(tbs);
        byte[] cert = Der.seq(tbs, sigAlg, Der.bitString(s.sign()));

        X509Certificate x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(cert));
        x509.verify(kp.getPublic()); // self-check: parses and its signature is valid
        return x509;
    }

    private static byte[] encodeName(CertInfo info) {
        ByteArrayOutputStream rdns = new ByteArrayOutputStream();
        if (!info.countryCode.isEmpty()) add(rdns, "2.5.4.6", Der.printable(info.countryCode));
        if (!info.state.isEmpty()) add(rdns, "2.5.4.8", Der.utf8(info.state));
        if (!info.city.isEmpty()) add(rdns, "2.5.4.7", Der.utf8(info.city));
        if (!info.organization.isEmpty()) add(rdns, "2.5.4.10", Der.utf8(info.organization));
        if (!info.orgUnit.isEmpty()) add(rdns, "2.5.4.11", Der.utf8(info.orgUnit));
        add(rdns, "2.5.4.3", Der.utf8(info.commonName));
        return Der.tlv(0x30, rdns.toByteArray());
    }

    private static void add(ByteArrayOutputStream out, String oid, byte[] value) {
        byte[] rdn = Der.set(Der.seq(Der.oid(oid), value));
        out.write(rdn, 0, rdn.length);
    }

    /** Extracts the BIT STRING contents (minus the unused-bits byte) from a SubjectPublicKeyInfo. */
    private static byte[] publicKeyBits(byte[] spki) {
        int[] pos = {0};
        readHeader(spki, pos);              // outer SEQUENCE
        int algLen = readHeader(spki, pos); // AlgorithmIdentifier
        pos[0] += algLen;
        int bitLen = readHeader(spki, pos); // BIT STRING
        byte[] bits = new byte[bitLen - 1];
        System.arraycopy(spki, pos[0] + 1, bits, 0, bits.length);
        return bits;
    }

    private static int readHeader(byte[] d, int[] pos) {
        pos[0]++; // tag
        int len = d[pos[0]++] & 0xFF;
        if (len >= 0x80) {
            int n = len & 0x7F;
            len = 0;
            for (int i = 0; i < n; i++) len = (len << 8) | (d[pos[0]++] & 0xFF);
        }
        return len;
    }
}
