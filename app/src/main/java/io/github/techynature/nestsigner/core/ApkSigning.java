package io.github.techynature.nestsigner.core;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.MinSdkVersionException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

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
        /** Name of the APK pulled out of a zip, or null if the file was already an APK. */
        public final String extractedFrom;

        Report(boolean v1, boolean v2, boolean v3, String signer, String certSha256, String extractedFrom) {
            this.v1 = v1;
            this.v2 = v2;
            this.v3 = v3;
            this.signer = signer;
            this.certSha256 = certSha256;
            this.extractedFrom = extractedFrom;
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

    /**
     * Signs {@code inputFile}. If it's a plain zip holding exactly one APK (like a GitHub
     * download), that APK is pulled out and signed instead. {@code workDir} holds temp files.
     */
    public static Report sign(File inputFile, File outputApk, KeystoreLoader.SigningKey key, File workDir)
            throws SignException {
        String extractedName = null;
        File apk = inputFile;
        File extracted = new File(workDir, "extracted.apk");
        try {
            String inner = findInnerApk(inputFile);
            if (inner != null) {
                extractEntry(inputFile, inner, extracted);
                apk = extracted;
                extractedName = inner.substring(inner.lastIndexOf('/') + 1);
            }
            return signApk(apk, outputApk, key, extractedName);
        } finally {
            //noinspection ResultOfMethodCallIgnored
            extracted.delete();
        }
    }

    /**
     * Returns null if the file is a real APK, or the entry name of the single APK inside a zip.
     * Throws a friendly error for anything else.
     */
    private static String findInnerApk(File file) throws SignException {
        ZipFile zip;
        try {
            zip = new ZipFile(file);
        } catch (Exception e) {
            throw new SignException("This file isn't an APK. Choose a file ending in .apk.", e);
        }
        try {
            if (zip.getEntry("AndroidManifest.xml") != null) return null; // a real APK

            List<String> apks = new ArrayList<>();
            Enumeration<? extends ZipEntry> en = zip.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (!e.isDirectory() && e.getName().toLowerCase(Locale.US).endsWith(".apk")) apks.add(e.getName());
            }
            if (apks.size() == 1) return apks.get(0);
            if (apks.size() > 1) {
                throw new SignException("This is a bundle with " + apks.size() + " APKs inside (like an XAPK or "
                        + "APKS file). NestSigner signs one APK at a time, so unzip it and sign each APK.", null);
            }
            throw new SignException("This is a zip file, not an APK. An APK has an AndroidManifest.xml inside, "
                    + "and this file doesn't.", null);
        } finally {
            try {
                zip.close();
            } catch (Exception ignored) {
                // nothing to do
            }
        }
    }

    private static void extractEntry(File zipFile, String entryName, File dest) throws SignException {
        try (ZipFile zip = new ZipFile(zipFile)) {
            ZipEntry entry = zip.getEntry(entryName);
            try (InputStream in = zip.getInputStream(entry); OutputStream out = new FileOutputStream(dest)) {
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            }
        } catch (Exception e) {
            throw new SignException("Couldn't unpack the APK from this zip.", e);
        }
    }

    private static Report signApk(File inputApk, File outputApk, KeystoreLoader.SigningKey key, String extractedName)
            throws SignException {
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
        } catch (Throwable e) {
            String why = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            throw new SignException("Signing failed: " + why, e);
        }

        // Check our own work with apksig's verifier
        ApkVerifier.Result result;
        try {
            result = new ApkVerifier.Builder(outputApk).build().verify();
        } catch (Throwable e) {
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
                sha256(cert),
                extractedName);
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
