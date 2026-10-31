package io.github.techynature.nestsigner.core;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the classic Java KeyStore (JKS) format, which Android can't open on its own.
 * The mirror image of {@link JksWriter}: same structure as the JDK's JavaKeyStore/KeyProtector.
 */
final class JksReader {

    static final int MAGIC = 0xFEEDFEED;
    private static final String KEY_PROTECTOR_OID = "1.3.6.1.4.1.42.2.17.1.1";

    static final class Entry {
        final byte[] protectedKey;
        final List<X509Certificate> chain;

        Entry(byte[] protectedKey, List<X509Certificate> chain) {
            this.protectedKey = protectedKey;
            this.chain = chain;
        }
    }

    private JksReader() {}

    /** Returns private-key entries by alias, after checking the keystore password. */
    static Map<String, Entry> read(byte[] data, char[] storePassword) throws KeystoreException {
        if (data.length < 32) {
            throw new KeystoreException(KeystoreException.Reason.CORRUPT, "This keystore file is empty or damaged.");
        }
        // Integrity check first, so a wrong password gives a clear message
        int bodyLen = data.length - 20;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] pw = passwordBytes(storePassword);
            md.update(pw);
            md.update("Mighty Aphrodite".getBytes(StandardCharsets.UTF_8));
            md.update(data, 0, bodyLen);
            Arrays.fill(pw, (byte) 0);
            byte[] expected = Arrays.copyOfRange(data, bodyLen, data.length);
            if (!MessageDigest.isEqual(md.digest(), expected)) {
                throw new KeystoreException(KeystoreException.Reason.WRONG_STORE_PASSWORD,
                        "Wrong keystore password.");
            }
        } catch (KeystoreException e) {
            throw e;
        } catch (Exception e) {
            throw new KeystoreException(KeystoreException.Reason.CORRUPT, "Couldn't read this keystore.", e);
        }

        Map<String, Entry> entries = new LinkedHashMap<>();
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(data, 0, bodyLen));
            if (in.readInt() != MAGIC) {
                throw new KeystoreException(KeystoreException.Reason.UNSUPPORTED, "This isn't a JKS keystore.");
            }
            int version = in.readInt();
            if (version != 1 && version != 2) {
                throw new KeystoreException(KeystoreException.Reason.UNSUPPORTED,
                        "Unsupported JKS version " + version + ".");
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            int count = in.readInt();
            for (int i = 0; i < count; i++) {
                int tag = in.readInt();
                String alias = in.readUTF();
                in.readLong(); // date
                if (tag == 1) {
                    byte[] key = new byte[in.readInt()];
                    in.readFully(key);
                    int chainLen = in.readInt();
                    List<X509Certificate> chain = new ArrayList<>();
                    for (int c = 0; c < chainLen; c++) {
                        chain.add(readCert(in, cf, version));
                    }
                    entries.put(alias, new Entry(key, chain));
                } else if (tag == 2) {
                    readCert(in, cf, version); // trusted certificate: not usable for signing
                } else {
                    throw new KeystoreException(KeystoreException.Reason.CORRUPT, "This keystore file is damaged.");
                }
            }
        } catch (KeystoreException e) {
            throw e;
        } catch (Exception e) {
            throw new KeystoreException(KeystoreException.Reason.CORRUPT, "This keystore file is damaged.", e);
        }
        return entries;
    }

    private static X509Certificate readCert(DataInputStream in, CertificateFactory cf, int version)
            throws Exception {
        if (version == 2) in.readUTF(); // certificate type, "X.509"
        byte[] enc = new byte[in.readInt()];
        in.readFully(enc);
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(enc));
    }

    /** Decrypts a key entry protected with Sun's JKS key protector. */
    static PrivateKey recoverKey(byte[] protectedKey, char[] keyPassword) throws KeystoreException {
        byte[] blob;
        try {
            blob = parseEncryptedPrivateKeyInfo(protectedKey);
        } catch (IOException e) {
            throw new KeystoreException(KeystoreException.Reason.UNSUPPORTED,
                    "This key uses a protection format NestSigner can't read.", e);
        }
        if (blob.length < 41) {
            throw new KeystoreException(KeystoreException.Reason.CORRUPT, "This key entry is damaged.");
        }
        byte[] pw = passwordBytes(keyPassword);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] salt = Arrays.copyOfRange(blob, 0, 20);
            byte[] encrypted = Arrays.copyOfRange(blob, 20, blob.length - 20);
            byte[] check = Arrays.copyOfRange(blob, blob.length - 20, blob.length);

            byte[] plain = new byte[encrypted.length];
            byte[] digest = salt;
            int pos = 0;
            while (pos < plain.length) {
                md.update(pw);
                md.update(digest);
                digest = md.digest();
                for (int i = 0; i < digest.length && pos < plain.length; i++, pos++) {
                    plain[pos] = (byte) (encrypted[pos] ^ digest[i]);
                }
            }
            md.update(pw);
            md.update(plain);
            if (!MessageDigest.isEqual(md.digest(), check)) {
                Arrays.fill(plain, (byte) 0);
                throw new KeystoreException(KeystoreException.Reason.WRONG_KEY_PASSWORD, "Wrong key password.");
            }
            PrivateKey key = toPrivateKey(plain);
            Arrays.fill(plain, (byte) 0);
            return key;
        } catch (KeystoreException e) {
            throw e;
        } catch (Exception e) {
            throw new KeystoreException(KeystoreException.Reason.CORRUPT, "Couldn't unlock this key.", e);
        } finally {
            Arrays.fill(pw, (byte) 0);
        }
    }

    private static PrivateKey toPrivateKey(byte[] pkcs8) throws KeystoreException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
        for (String alg : new String[] {"RSA", "EC", "DSA"}) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (Exception ignored) {
                // try the next algorithm
            }
        }
        throw new KeystoreException(KeystoreException.Reason.UNSUPPORTED, "This key type isn't supported.");
    }

    /** SEQUENCE { SEQUENCE { OID, params }, OCTET STRING } -> the OCTET STRING contents. */
    private static byte[] parseEncryptedPrivateKeyInfo(byte[] der) throws IOException {
        int[] pos = {0};
        expect(der, pos, 0x30);
        readLength(der, pos);
        expect(der, pos, 0x30);
        int algEnd = readLength(der, pos) + pos[0];
        expect(der, pos, 0x06);
        int oidLen = readLength(der, pos);
        if (pos[0] + oidLen > der.length) throw new IOException("Truncated key");
        byte[] oid = Arrays.copyOfRange(der, pos[0], pos[0] + oidLen);
        byte[] expected = Der.oid(KEY_PROTECTOR_OID);
        if (!Arrays.equals(Arrays.copyOfRange(expected, 2, expected.length), oid)) {
            throw new IOException("Unknown key protection algorithm");
        }
        pos[0] = algEnd;
        expect(der, pos, 0x04);
        int len = readLength(der, pos);
        if (pos[0] + len > der.length) throw new IOException("Truncated key");
        return Arrays.copyOfRange(der, pos[0], pos[0] + len);
    }

    private static void expect(byte[] d, int[] pos, int tag) throws IOException {
        if (pos[0] >= d.length || (d[pos[0]] & 0xFF) != tag) throw new IOException("Unexpected DER tag");
        pos[0]++;
    }

    private static int readLength(byte[] d, int[] pos) throws IOException {
        if (pos[0] >= d.length) throw new IOException("Truncated DER");
        int len = d[pos[0]++] & 0xFF;
        if (len < 0x80) return len;
        int n = len & 0x7F;
        if (n == 0 || n > 4) throw new IOException("Bad DER length");
        len = 0;
        for (int i = 0; i < n; i++) {
            if (pos[0] >= d.length) throw new IOException("Truncated DER");
            len = (len << 8) | (d[pos[0]++] & 0xFF);
        }
        return len;
    }

    private static byte[] passwordBytes(char[] password) {
        byte[] b = new byte[password.length * 2];
        for (int i = 0, j = 0; i < password.length; i++) {
            b[j++] = (byte) (password[i] >> 8);
            b[j++] = (byte) password[i];
        }
        return b;
    }
}
