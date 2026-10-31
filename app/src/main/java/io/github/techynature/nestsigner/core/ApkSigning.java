package io.github.techynature.nestsigner.core;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.MinSdkVersionException;

import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Signs an APK with v1 (JAR), v2 and v3 signatures using Google's apksig library —
 * the same engine behind the SDK's apksigner tool and Android Studio.
 */
public final class ApkSigning {

    /** What happened, for showing to the user. */
    public static final class Report {
        public final boolean v1, v2, v3;
        public final String signer;
        public final String certSha256;

        Report(boolean v1, boolean v2, boolean v3, String signer, String certSha256) {
            this.v1 = v1;
            this.v2 = v2;
            this.v3 = v3;
            this.signer = signer;
            this.certSha256 = certSha256;
        }

        public String schemes() {
            StringBuilder sb = new StringBuilder();
            if (v1) sb.append("v1 ");
            if (v2) sb.append("v2 ");
            if (v3) sb.append("v3 ");
            return sb.toString().trim();
        }
    }

    /** A signing failure with a message that's safe to show to the user. */
    public static final class SignException extends Exception {
        public SignException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private ApkSigning() {}

    public static Report sign(File inputApk, File outputApk, KeystoreLoader.SigningKey key) throws SignException {
        List<X509Certificate> certs = key.certificates;
        try {
            ApkSigner.SignerConfig config =
                    new ApkSigner.SignerConfig.Builder("CERT", key.privateKey, certs).build();
            new ApkSigner.Builder(Collections.singletonList(config))
                    .setInputApk(inputApk)
                    .setOutputApk(outputApk)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .setV4SigningEnabled(false)
                    .setCreatedBy("NestSigner")
                    .build()
                    .sign();
        } catch (MinSdkVersionException e) {
            throw new SignException("Couldn't read this APK's minimum Android version. Is it a complete APK?", e);
        } catch (ApkFormatException e) {
            throw new SignException("This file isn't a valid APK.", e);
        } catch (Exception e) {
            String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            throw new SignException("Signing failed: " + why, e);
        }

        // Check our own work with apksig's verifier
        ApkVerifier.Result result;
        try {
            result = new ApkVerifier.Builder(outputApk).build().verify();
        } catch (Exception e) {
            throw new SignException("The APK was signed, but checking the signature failed.", e);
        }
        if (!result.isVerified()) {
            String detail = result.getErrors().isEmpty() ? "" : " " + result.getErrors().get(0);
            throw new SignException("The signed APK didn't pass verification." + detail, null);
        }

        X509Certificate cert = certs.get(0);
        return new Report(
                result.isVerifiedUsingV1Scheme(),
                result.isVerifiedUsingV2Scheme(),
                result.isVerifiedUsingV3Scheme(),
                cert.getSubjectX500Principal().getName(),
                sha256(cert));
    }

    private static String sha256(X509Certificate cert) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < d.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format(Locale.US, "%02X", d[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "(unavailable)";
        }
    }
}
