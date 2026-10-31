package io.github.techynature.nestsigner.core;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;

/**
 * Writes the classic Java KeyStore (JKS) file format.
 *
 * Android has no built-in JKS provider, so the format is written by hand here.
 * It matches what the JDK's sun.security.provider.JavaKeyStore and KeyProtector produce,
 * so keytool, jarsigner, apksigner, Gradle and Android Studio all read it normally.
 */
final class JksWriter {

    private static final int MAGIC = 0xFEEDFEED;
    private static final int VERSION_2 = 2;
    private static final int PRIVATE_KEY_ENTRY = 1;
    private static final String KEY_PROTECTOR_OID = "1.3.6.1.4.1.42.2.17.1.1";
    private static final int SALT_LEN = 20;

    private JksWriter() {}

    static byte[] write(String alias, PrivateKey key, char[] keyPassword, Certificate[] chain,
                        char[] storePassword, Date created, SecureRandom rnd)
            throws GeneralSecurityException, IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buf);

        out.writeInt(MAGIC);
        out.writeInt(VERSION_2);
        out.writeInt(1); // one entry

        out.writeInt(PRIVATE_KEY_ENTRY);
        out.writeUTF(alias);
        out.writeLong(created.getTime());
        byte[] protectedKey = protect(key.getEncoded(), keyPassword, rnd);
        out.writeInt(protectedKey.length);
        out.write(protectedKey);
        out.writeInt(chain.length);
        for (Certificate c : chain) {
            byte[] enc = c.getEncoded();
            out.writeUTF(c.getType()); // "X.509"
            out.writeInt(enc.length);
            out.write(enc);
        }
        out.flush();

        // Integrity check: SHA-1(password bytes + "Mighty Aphrodite" + everything so far)
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] pw = passwordBytes(storePassword);
        md.update(pw);
        md.update("Mighty Aphrodite".getBytes(StandardCharsets.UTF_8));
        md.update(buf.toByteArray());
        Arrays.fill(pw, (byte) 0);
        out.write(md.digest());
        out.flush();
        return buf.toByteArray();
    }

    /** Sun's proprietary key protection, wrapped in an EncryptedPrivateKeyInfo. */
    private static byte[] protect(byte[] plainKey, char[] password, SecureRandom rnd)
            throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] pw = passwordBytes(password);

        byte[] salt = new byte[SALT_LEN];
        rnd.nextBytes(salt);

        int rounds = plainKey.length / 20 + (plainKey.length % 20 != 0 ? 1 : 0);
        byte[] xorKey = new byte[plainKey.length];
        byte[] digest = salt;
        int pos = 0;
        for (int i = 0; i < rounds; i++) {
            md.update(pw);
            md.update(digest);
            digest = md.digest();
            int n = Math.min(digest.length, xorKey.length - pos);
            System.arraycopy(digest, 0, xorKey, pos, n);
            pos += n;
        }

        byte[] encrypted = new byte[plainKey.length];
        for (int i = 0; i < plainKey.length; i++) encrypted[i] = (byte) (plainKey[i] ^ xorKey[i]);

        md.update(pw);
        md.update(plainKey);
        byte[] check = md.digest();

        byte[] blob = Der.concat(salt, encrypted, check);
        Arrays.fill(pw, (byte) 0);
        Arrays.fill(xorKey, (byte) 0);

        return Der.seq(
                Der.seq(Der.oid(KEY_PROTECTOR_OID), Der.nul()),
                Der.octetString(blob));
    }

    /** Each char as two bytes, big-endian — the way the JDK feeds JKS passwords to SHA-1. */
    private static byte[] passwordBytes(char[] password) {
        byte[] b = new byte[password.length * 2];
        for (int i = 0, j = 0; i < password.length; i++) {
            b[j++] = (byte) (password[i] >> 8);
            b[j++] = (byte) password[i];
        }
        return b;
    }
}
