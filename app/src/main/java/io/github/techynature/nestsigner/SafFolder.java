package io.github.techynature.nestsigner;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import io.github.techynature.nestsigner.core.FolderPacker;

/** Lists every file under a folder picked with the system folder picker. */
final class SafFolder {

    private static final int MAX_FILES = 100_000;

    private SafFolder() {}

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

    static List<FolderPacker.Item> list(Context ctx, Uri treeUri) throws IOException {
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
            try (Cursor c = cr.query(children, columns, null, null, null)) {
                if (c == null) throw new IOException("Couldn't list the folder.");
                while (c.moveToNext()) {
                    String id = c.getString(0);
                    String name = c.getString(1);
                    String mime = c.getString(2);
                    if (id == null || name == null) continue;
                    String path = dir[1] + name;
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
                                InputStream in = cr.openInputStream(fileUri);
                                if (in == null) throw new FileNotFoundException(path);
                                return in;
                            }
                        });
                        if (items.size() > MAX_FILES) {
                            throw new IOException("This folder has too many files to be an APK.");
                        }
                    }
                }
            }
        }
        return items;
    }
}
