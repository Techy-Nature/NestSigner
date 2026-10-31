package io.github.techynature.nestsigner;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.DocumentsContract;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import io.github.techynature.nestsigner.core.FolderPacker;

/**
 * Lists every file under a folder picked with the system folder picker.
 *
 * With "All files access" granted, the folder is read directly from storage, which is much
 * faster for big folders. Otherwise it goes through the picker's storage service, retrying
 * when that service briefly stops responding (common with thousands of files).
 */
final class SafFolder {

    private static final int MAX_FILES = 200_000;
    private static final String EXTERNAL_STORAGE_AUTHORITY = "com.android.externalstorage.documents";

    private SafFolder() {}

    /** True if NestSigner may read storage directly (Android 11+ "All files access"). */
    static boolean hasAllFilesAccess() {
        return Build.VERSION.SDK_INT >= 30 && Environment.isExternalStorageManager();
    }

    static String displayName(Context ctx, Uri treeUri) {
        try {
            Uri doc = DocumentsContract.buildDocumentUriUsingTree(treeUri, DocumentsContract.getTreeDocumentId(treeUri));
            try (Cursor c = ctx.getContentResolver().query(doc,
                    new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME}, null, null, null)) {
                if (c != null && c.moveToFirst() && c.getString(0) != null) return c.getString(0);
            }
        } catch (Throwable ignored) {
            // fall through
        }
        return "folder";
    }

    /** Lists the folder's files, reading directly when allowed and falling back to the picker service. */
    static List<FolderPacker.Item> list(Context ctx, Uri treeUri) throws IOException {
        File direct = directPath(treeUri);
        if (direct != null) return listDirect(direct);
        return listViaProvider(ctx, treeUri);
    }

    /** Whether the next {@link #list} will read storage directly. */
    static boolean willReadDirectly(Uri treeUri) {
        return directPath(treeUri) != null;
    }

    // ---------- direct reading ----------

    /** Maps a picked folder on internal storage or an SD card to a real path, if we may read it. */
    private static File directPath(Uri treeUri) {
        if (!hasAllFilesAccess() || !EXTERNAL_STORAGE_AUTHORITY.equals(treeUri.getAuthority())) return null;
        try {
            String id = DocumentsContract.getTreeDocumentId(treeUri); // e.g. "primary:Projects/apk"
            int colon = id.indexOf(':');
            if (colon < 0) return null;
            String volume = id.substring(0, colon);
            String rel = id.substring(colon + 1);
            File base = "primary".equalsIgnoreCase(volume)
                    ? Environment.getExternalStorageDirectory()
                    : new File("/storage/" + volume);
            File dir = rel.isEmpty() ? base : new File(base, rel);
            return dir.isDirectory() && dir.canRead() && dir.list() != null ? dir : null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static List<FolderPacker.Item> listDirect(File root) throws IOException {
        List<FolderPacker.Item> items = new ArrayList<>();
        Deque<Object[]> pending = new ArrayDeque<>(); // {File dir, String relative prefix}
        pending.push(new Object[] {root, ""});
        while (!pending.isEmpty()) {
            Object[] d = pending.pop();
            File[] kids = ((File) d[0]).listFiles();
            if (kids == null) continue;
            for (File f : kids) {
                final String path = d[1] + f.getName();
                if (f.isDirectory()) {
                    pending.push(new Object[] {f, path + "/"});
                } else {
                    items.add(new FolderPacker.Item() {
                        @Override
                        public String path() {
                            return path;
                        }

                        @Override
                        public InputStream open() throws IOException {
                            return new FileInputStream(f);
                        }
                    });
                    if (items.size() > MAX_FILES) throw new IOException("This folder has too many files to be an APK.");
                }
            }
        }
        return items;
    }

    // ---------- through the picker's storage service ----------

    private static List<FolderPacker.Item> listViaProvider(Context ctx, Uri treeUri) throws IOException {
        ContentResolver cr = ctx.getContentResolver();
        List<FolderPacker.Item> items = new ArrayList<>();

        Deque<String[]> pending = new ArrayDeque<>(); // {documentId, relative path prefix}
        pending.push(new String[] {DocumentsContract.getTreeDocumentId(treeUri), ""});
        String[] columns = {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE};

        while (!pending.isEmpty()) {
            String[] dir = pending.pop();
            Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, dir[0]);
            Cursor c = queryWithRetry(cr, children, columns);
            try {
                while (c.moveToNext()) {
                    String id = c.getString(0);
                    String name = c.getString(1);
                    String mime = c.getString(2);
                    if (id == null || name == null) continue;
                    final String path = dir[1] + name;
                    if (DocumentsContract.Document.MIME_TYPE_DIR.equals(mime)) {
                        pending.push(new String[] {id, path + "/"});
                    } else {
                        final Uri fileUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, id);
                        items.add(new FolderPacker.Item() {
                            @Override
                            public String path() {
                                return path;
                            }

                            @Override
                            public InputStream open() throws IOException {
                                return openWithRetry(cr, fileUri, path);
                            }
                        });
                        if (items.size() > MAX_FILES) {
                            throw new IOException("This folder has too many files to be an APK.");
                        }
                    }
                }
            } finally {
                c.close();
            }
        }
        return items;
    }

    private static final long[] BACKOFF_MS = {250, 750, 1500, 3000, 5000};

    /** The storage service can drop out under heavy use and restart; wait and try again. */
    private static InputStream openWithRetry(ContentResolver cr, Uri uri, String path) throws IOException {
        Throwable last = null;
        for (int attempt = 0; attempt <= BACKOFF_MS.length; attempt++) {
            try {
                InputStream in = cr.openInputStream(uri);
                if (in != null) return in;
                last = new FileNotFoundException(path);
            } catch (FileNotFoundException | SecurityException | IllegalStateException e) {
                last = e;
                if (!isTransient(e)) break;
            }
            if (attempt < BACKOFF_MS.length) sleep(BACKOFF_MS[attempt]);
        }
        throw new IOException("Couldn't open " + path + ": " + (last == null ? "unknown error" : last.getMessage()), last);
    }

    private static Cursor queryWithRetry(ContentResolver cr, Uri uri, String[] columns) throws IOException {
        Throwable last = null;
        for (int attempt = 0; attempt <= BACKOFF_MS.length; attempt++) {
            try {
                Cursor c = cr.query(uri, columns, null, null, null);
                if (c != null) return c;
            } catch (Throwable t) {
                last = t;
            }
            if (attempt < BACKOFF_MS.length) sleep(BACKOFF_MS[attempt]);
        }
        throw new IOException("Couldn't list the folder: No content provider", last);
    }

    private static boolean isTransient(Throwable e) {
        String m = String.valueOf(e.getMessage());
        return m.contains("No content provider") || m.contains("dead") || m.contains("Binder")
                || e instanceof IllegalStateException;
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
}
