package io.github.techynature.nestsigner.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

/** Opens JKS, PKCS #12 and BKS keystores and unlocks a signing key from them. */
public final class KeystoreLoader {

    private static final int JCEKS_MAGIC = 0xCECECECE;

    /** A private key and its certificate chain, ready to sign with. */
    public static final class SigningKey {
        public final PrivateKey privateKey;
        public final List<X509Certificate> certificates;

        SigningKey(PrivateKey privateKey, List<X509Certificate> certificates) {
            this.privateKey = privateKey;
            this.certificates = Collections.unmodifiableList(certificates);
        }
    }

    /** An opened keystore. Keys stay locked until {@link #unlock} is called. */
    public static final class Opened {
        public final String type;
        public final List<String> aliases;
        private final Map<String, JksReader.Entry> jksEntries; // JKS only
        private final KeyStore platformStore;                   // PKCS12 / BKS only

        Opened(String type, List<String> aliases, Map<String, JksReader.Entry> jksEntries, KeyStore platformStore) {
            this.type = type;
            this.aliases = Collections.unmodifiableList(aliases);
            this.jksEntries = jksEntries;
            this.platformStore = platformStore;
        }

        public SigningKey unlock(String alias, char[] keyPassword) throws KeystoreException {
            if (jksEntries != null) {
                JksReader.Entry e = jksEntries.get(alias);
                if (e == null) throw noSuchAlias(alias);
                if (e.chain.isEmpty()) {
                    throw new KeystoreException(KeystoreException.Reason.CORRUPT, "This key has no certificate.");
                }
                return new SigningKey(JksReader.recoverKey(e.protectedKey, keyPassword), new ArrayList<>(e.chain));
            }
            try {
                Key key = platformStore.getKey(alias, keyPassword);
                if (!(key instanceof PrivateKey)) throw noSuchAlias(alias);
                Certificate[] chain = platformStore.getCertificateChain(alias);
                if (chain == null || chain.length == 0) {
                    throw new KeystoreException(KeystoreException.Reason.CORRUPT, "This key has no certificate.");
                }
                List<X509Certificate> certs = new ArrayList<>();
                for (Certificate c : chain) certs.add((X509Certificate) c);
                return new SigningKey((PrivateKey) key, certs);
            } catch (UnrecoverableKeyException e) {
                throw new KeystoreException(KeystoreException.Reason.WRONG_KEY_PASSWORD, "Wrong key password.", e);
            } catch (KeystoreException e) {
                throw e;
            } catch (Exception e) {
                throw new KeystoreException(KeystoreException.Reason.CORRUPT, "Couldn't unlock this key.", e);
            }
        }
    }

    private KeystoreLoader() {}

    public static Opened open(byte[] data, char[] storePassword) throws KeystoreException {
        int magic = data.length >= 4
                ? ((data[0] & 0xFF) << 24) | ((data[1] & 0xFF) << 16) | ((data[2] & 0xFF) << 8) | (data[3] & 0xFF)
                : 0;

        if (magic == JksReader.MAGIC) {
            Map<String, JksReader.Entry> entries = JksReader.read(data, storePassword);
            return finish("JKS", new ArrayList<>(entries.keySet()), entries, null);
        }
        if (magic == JCEKS_MAGIC) {
            throw new KeystoreException(KeystoreException.Reason.UNSUPPORTED,
                    "JCEKS keystores aren't supported. Convert it to JKS or PKCS12 first.");
        }

        // PKCS #12 starts with a DER SEQUENCE; anything else gets one try as BKS
        String[] types = data.length > 0 && (data[0] & 0xFF) == 0x30
                ? new String[] {"PKCS12"} : new String[] {"BKS"};
        KeystoreException last = null;
        for (String type : types) {
            try {
                KeyStore ks = KeyStore.getInstance(type);
                ks.load(new ByteArrayInputStream(data), storePassword);
                List<String> aliases = new ArrayList<>();
                Enumeration<String> en = ks.aliases();
                while (en.hasMoreElements()) {
                    String a = en.nextElement();
                    if (ks.isKeyEntry(a)) aliases.add(a);
                }
                return finish(type, aliases, null, ks);
            } catch (IOException e) {
                Throwable cause = e.getCause();
                String msg = String.valueOf(e.getMessage()).toLowerCase();
                if (cause instanceof UnrecoverableKeyException
                        || msg.contains("password") || msg.contains("integrity") || msg.contains("mac invalid")) {
                    throw new KeystoreException(KeystoreException.Reason.WRONG_STORE_PASSWORD,
                            "Wrong keystore password.", e);
                }
                last = new KeystoreException(KeystoreException.Reason.UNSUPPORTED,
                        "This doesn't look like a keystore NestSigner can open (JKS, PKCS12 or BKS).", e);
            } catch (Exception e) {
                last = new KeystoreException(KeystoreException.Reason.UNSUPPORTED,
                        "This doesn't look like a keystore NestSigner can open (JKS, PKCS12 or BKS).", e);
            }
        }
        throw last;
    }

    private static Opened finish(String type, List<String> aliases, Map<String, JksReader.Entry> jks, KeyStore ks)
            throws KeystoreException {
        if (aliases.isEmpty()) {
            throw new KeystoreException(KeystoreException.Reason.NO_KEYS,
                    "This keystore has no private keys, so it can't sign anything.");
        }
        return new Opened(type, aliases, jks, ks);
    }

    private static KeystoreException noSuchAlias(String alias) {
        return new KeystoreException(KeystoreException.Reason.NO_KEYS, "There's no key named \"" + alias + "\".");
    }
}
