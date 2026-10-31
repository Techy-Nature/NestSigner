package io.github.techynature.nestsigner.core;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Packs an unzipped APK folder back into an APK file (unsigned and unaligned —
 * {@link ApkSigning} aligns and signs it afterwards).
 *
 * Works on a plain list of files so it doesn't care whether they come from
 * java.io.File or Android's file picker.
 */
public final class FolderPacker {

    /** One file in the folder, with its path relative to the folder ("res/layout/main.xml"). */
    public interface Item {
        String path();

        InputStream open() throws IOException;
    }

    /** A packing failure with a message that's safe to show to the user. */
    public static final class PackException extends Exception {
        public PackException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Extensions aapt stores uncompressed. Media must stay uncompressed so apps can open it
     * with file descriptors; resources.arsc must be stored for Android 11+ installs; native
     * libraries are stored so they work whether or not the app extracts them.
     */
    private static final Set<String> STORED_EXTENSIONS = new HashSet<>(Arrays.asList(
            "arsc", "so",
            "jpg", "jpeg", "png", "gif", "webp",
            "wav", "mp2", "mp3", "ogg", "aac", "mid", "midi", "smf", "jet", "rtttl", "imy", "xmf",
            "mpg", "mpeg", "mp4", "m4a", "m4v", "3gp", "3gpp", "3g2", "3gpp2", "amr", "awb",
            "wma", "wmv", "webm", "mkv"));

    private FolderPacker() {}

    /** Told how far packing has got, so big folders don't look frozen. */
    public interface Progress {
        void onProgress(int done, int total);
    }

    /** Packs the items into {@code outApk}. Returns how many files were packed. */
    public static int pack(List<Item> items, File outApk) throws PackException {
        return pack(items, outApk, null);
    }

    /** Packs the items into {@code outApk}, reporting progress. Returns how many files were packed. */
    public static int pack(List<Item> items, File outApk, Progress progress) throws PackException {
        String prefix = findApkRoot(items);

        List<Item> chosen = new ArrayList<>();
        List<String> names = new ArrayList<>();
        for (Item it : items) {
            String p = normalize(it.path());
            if (p == null || !p.startsWith(prefix)) continue;
            String name = p.substring(prefix.length());
            if (name.isEmpty() || isOldSignatureFile(name)) continue;
            chosen.add(it);
            names.add(name);
        }

        checkNotDecompiled(items, prefix, chosen, names);

        // Conventional order: manifest, dex files, resources table, then everything else
        Integer[] order = new Integer[names.size()];
        for (int i = 0; i < order.length; i++) order[i] = i;
        Arrays.sort(order, (a, b) -> {
            int ra = rank(names.get(a)), rb = rank(names.get(b));
            return ra != rb ? Integer.compare(ra, rb) : names.get(a).compareTo(names.get(b));
        });

        // STORED entries need their size and CRC before their data, so each one is copied to this
        // spill file while measuring it. That way every source file is opened only once.
        File spill = new File(outApk.getParentFile(), outApk.getName() + ".part");
        String current = null;
        int done = 0;
        int total = order.length;
        try (ZipOutputStream zip = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(outApk), 1 << 16))) {
            byte[] buf = new byte[64 * 1024];
            for (int idx : order) {
                Item it = chosen.get(idx);
                String name = names.get(idx);
                current = name;
                ZipEntry entry = new ZipEntry(name);
                entry.setTime(0L);
                if (shouldStore(name)) {
                    CRC32 crc = new CRC32();
                    long size = 0;
                    try (InputStream in = it.open(); OutputStream tmp = new FileOutputStream(spill)) {
                        int n;
                        while ((n = in.read(buf)) > 0) {
                            crc.update(buf, 0, n);
                            tmp.write(buf, 0, n);
                            size += n;
                        }
                    }
                    entry.setMethod(ZipEntry.STORED);
                    entry.setSize(size);
                    entry.setCompressedSize(size);
                    entry.setCrc(crc.getValue());
                    zip.putNextEntry(entry);
                    try (InputStream in = new FileInputStream(spill)) {
                        int n;
                        while ((n = in.read(buf)) > 0) zip.write(buf, 0, n);
                    }
                } else {
                    entry.setMethod(ZipEntry.DEFLATED);
                    zip.putNextEntry(entry);
                    try (InputStream in = it.open()) {
                        int n;
                        while ((n = in.read(buf)) > 0) zip.write(buf, 0, n);
                    }
                }
                zip.closeEntry();
                done++;
                if (progress != null && (done % 25 == 0 || done == total)) progress.onProgress(done, total);
            }
        } catch (IOException e) {
            String where = current == null ? "" : " while reading " + current;
            throw new PackException("Couldn't pack the folder" + where + ". " + friendlyCause(e), e);
        } finally {
            //noinspection ResultOfMethodCallIgnored
            spill.delete();
        }
        return chosen.size();
    }

    private static String friendlyCause(IOException e) {
        String m = String.valueOf(e.getMessage());
        if (m.contains("No content provider") || m.contains("dead") || m.contains("Binder")) {
            return "Android's storage service stopped responding. Try again, or allow All files access "
                    + "in NestSigner for big folders.";
        }
        if (m.contains("ENOSPC") || m.toLowerCase(Locale.US).contains("no space")) {
            return "The device ran out of storage space.";
        }
        return m;
    }

    /**
     * Finds where AndroidManifest.xml is: at the top of the chosen folder, or one level down
     * (if the user picked the folder that contains the APK folder). Returns the path prefix.
     */
    private static String findApkRoot(List<Item> items) throws PackException {
        List<String> found = new ArrayList<>();
        for (Item it : items) {
            String p = normalize(it.path());
            if (p == null) continue;
            if (p.equals("AndroidManifest.xml")) return "";
            String[] parts = p.split("/");
            if (parts.length == 2 && parts[1].equals("AndroidManifest.xml")) found.add(parts[0] + "/");
        }
        if (found.size() == 1) return found.get(0);
        if (found.size() > 1) {
            Collections.sort(found);
            throw new PackException("This folder holds several APK folders (" + String.join(", ", found)
                    + "). Choose just one of them.", null);
        }
        throw new PackException("There's no AndroidManifest.xml in this folder, so it isn't an unzipped APK. "
                + "Choose the folder you got by unzipping an APK.", null);
    }

    /** Apktool projects have text XML and smali, which need recompiling, not just zipping. */
    private static void checkNotDecompiled(List<Item> all, String prefix, List<Item> chosen, List<String> names)
            throws PackException {
        boolean apktoolYml = false, smali = false;
        for (String n : names) {
            if (n.equals("apktool.yml")) apktoolYml = true;
            if (n.startsWith("smali/") || n.matches("smali_classes\\d+/.*")) smali = true;
        }
        boolean textManifest = false;
        int m = names.indexOf("AndroidManifest.xml");
        if (m >= 0) {
            try (InputStream in = chosen.get(m).open()) {
                int first = in.read();
                // Compiled (binary) manifests start with 0x03 0x00; text XML starts with '<' or a BOM/space
                textManifest = first == '<' || first == 0xEF || first == ' ' || first == '\n' || first == '\r';
            } catch (IOException e) {
                throw new PackException("Couldn't read AndroidManifest.xml.", e);
            }
        }
        if (apktoolYml || smali || textManifest) {
            throw new PackException("This looks like a decompiled (apktool) project, not an unzipped APK. "
                    + "Its code and XML need recompiling, which NestSigner can't do. Rebuild it with "
                    + "apktool (\"apktool b\"), then sign the APK it makes.", null);
        }
    }

    private static boolean isOldSignatureFile(String name) {
        if (!name.startsWith("META-INF/") || name.indexOf('/', 9) >= 0) return false;
        String upper = name.toUpperCase(Locale.US);
        return upper.equals("META-INF/MANIFEST.MF") || upper.endsWith(".SF") || upper.endsWith(".RSA")
                || upper.endsWith(".DSA") || upper.endsWith(".EC");
    }

    private static boolean shouldStore(String name) {
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot < name.lastIndexOf('/')) return false;
        return STORED_EXTENSIONS.contains(name.substring(dot + 1).toLowerCase(Locale.US));
    }

    private static int rank(String name) {
        if (name.equals("AndroidManifest.xml")) return 0;
        if (name.matches("classes\\d*\\.dex")) return 1;
        if (name.equals("resources.arsc")) return 2;
        return 3;
    }

    /** Forward slashes, no leading slash, and nothing that climbs out of the folder. */
    private static String normalize(String path) {
        if (path == null) return null;
        String p = path.replace('\\', '/');
        while (p.startsWith("/")) p = p.substring(1);
        for (String part : p.split("/")) {
            if (part.equals("..") || part.equals(".")) return null;
        }
        return p;
    }
}
