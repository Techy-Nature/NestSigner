package io.github.techynature.nestsigner.core;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/** One call that turns form input into the bytes of a ready-to-use .jks file. */
public final class KeystoreFactory {

    public static final int KEY_SIZE = 2048;

    private KeystoreFactory() {}

    public static final class Result {
        public final byte[] jksBytes;
        public final String alias;
        public final String subject;
        public final Date notAfter;
        public final String sha1;
        public final String sha256;

        Result(byte[] jksBytes, String alias, String subject, Date notAfter, String sha1, String sha256) {
            this.jksBytes = jksBytes;
            this.alias = alias;
            this.subject = subject;
            this.notAfter = notAfter;
            this.sha1 = sha1;
            this.sha256 = sha256;
        }
    }

    /** JKS stores aliases in lowercase; keytool does the same, so match it. */
    public static String normalizeAlias(String alias) {
        return alias == null ? "" : alias.trim().toLowerCase(Locale.ENGLISH);
    }

    /** Returns an error message, or null if the alias is fine. */
    public static String validateAlias(String alias) {
        String a = normalizeAlias(alias);
        if (a.isEmpty()) return "Enter a key alias, like key0 or upload.";
        if (a.length() > 64) return "Alias must be 64 characters or fewer.";
        if (!a.matches("[a-z0-9._-]+")) return "Alias can only use letters, numbers, dots, dashes and underscores.";
        return null;
    }

    public static Result create(String alias, char[] storePassword, char[] keyPassword,
                                CertInfo info, int validityYears) throws Exception {
        SecureRandom rnd = new SecureRandom();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(KEY_SIZE, rnd);
        KeyPair kp = kpg.generateKeyPair();

        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.US);
        cal.set(Calendar.MILLISECOND, 0);
        Date notBefore = cal.getTime();
        cal.add(Calendar.YEAR, validityYears);
        Date notAfter = cal.getTime();

        X509Certificate cert = CertBuilder.build(kp, info, notBefore, notAfter, rnd);
        String a = normalizeAlias(alias);
        byte[] jks = JksWriter.write(a, kp.getPrivate(), keyPassword,
                new Certificate[] {cert}, storePassword, notBefore, rnd);

        return new Result(jks, a, info.toDisplayString(), notAfter,
                fingerprint(cert, "SHA-1"), fingerprint(cert, "SHA-256"));
    }

    private static String fingerprint(X509Certificate cert, String alg) throws Exception {
        byte[] d = MessageDigest.getInstance(alg).digest(cert.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < d.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format(Locale.US, "%02X", d[i]));
        }
        return sb.toString();
    }
}
