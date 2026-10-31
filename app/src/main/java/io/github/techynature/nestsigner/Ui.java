package io.github.techynature.nestsigner;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.view.View;
import android.view.ViewParent;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/** Small helpers shared by both screens. */
final class Ui {

    private Ui() {}

    /** Scrolls so that {@code target} is at the top, however deeply it's nested. */
    static void scrollTo(ScrollView root, View target) {
        root.post(() -> {
            int y = 0;
            View v = target;
            while (v != null && v != root) {
                y += v.getTop();
                ViewParent p = v.getParent();
                v = p instanceof View ? (View) p : null;
            }
            root.smoothScrollTo(0, Math.max(0, y - 24));
        });
    }

    static void setPasswordsVisible(boolean visible, EditText... fields) {
        int type = InputType.TYPE_CLASS_TEXT | (visible
                ? InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                : InputType.TYPE_TEXT_VARIATION_PASSWORD);
        for (EditText e : fields) {
            int sel = e.getSelectionEnd();
            e.setInputType(type);
            e.setSelection(Math.max(0, sel));
        }
    }

    // ---------- saving through the file picker ----------

    /**
     * Copies {@code source} into a document the user picked, then checks the data really landed.
     * Some file providers reject the "wt" mode, so plain "w" is tried first and "rwt" as a fallback.
     */
    static void writeToDocument(Context ctx, File source, Uri target) throws IOException {
        long expected = source.length();
        OutputStream out = null;
        IOException firstFailure = null;
        for (String mode : new String[] {"w", "rwt", "wt"}) {
            try {
                out = ctx.getContentResolver().openOutputStream(target, mode);
                if (out != null) break;
            } catch (Exception e) {
                if (firstFailure == null) firstFailure = new IOException("Couldn't open the save location (" + mode + ")", e);
            }
        }
        if (out == null) {
            throw firstFailure != null ? firstFailure : new IOException("The file picker gave no place to save.");
        }
        try (InputStream in = new FileInputStream(source); OutputStream o = out) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
            o.flush();
        }
        long written = documentSize(ctx, target);
        if (written >= 0 && written != expected) {
            throw new IOException("Saved file is " + written + " bytes but should be " + expected
                    + ". The storage location may not have accepted it.");
        }
    }

    /** Size reported by the document's provider, or -1 if it doesn't say. */
    static long documentSize(Context ctx, Uri uri) {
        try (Cursor c = ctx.getContentResolver().query(uri, new String[] {OpenableColumns.SIZE}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return c.getLong(0);
        } catch (Throwable ignored) {
            // provider doesn't report sizes
        }
        return -1;
    }

    // ---------- error reporting ----------

    /** A popup with the friendly message plus technical details the user can copy and share. */
    static void showProblem(Activity activity, String title, String message, Throwable t) {
        if (activity.isFinishing()) return;
        final String details = technicalDetails(message, t);
        new AlertDialog.Builder(activity)
                .setTitle(title)
                .setMessage(message + (t != null ? "\n\nTap \"Copy details\" to share what went wrong." : ""))
                .setPositiveButton("OK", null)
                .setNeutralButton("Copy details", (d, w) -> {
                    ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(ClipData.newPlainText("NestSigner error", details));
                        if (Build.VERSION.SDK_INT < 33) Toast.makeText(activity, "Copied", Toast.LENGTH_SHORT).show();
                    }
                })
                .show();
    }

    static String technicalDetails(String message, Throwable t) {
        StringBuilder sb = new StringBuilder();
        sb.append("NestSigner ").append(BuildConfigInfo.version())
                .append(" · Android ").append(Build.VERSION.RELEASE)
                .append(" (API ").append(Build.VERSION.SDK_INT).append(") · ")
                .append(Build.MANUFACTURER).append(' ').append(Build.MODEL)
                .append("\n").append(message);
        int depth = 0;
        for (Throwable c = t; c != null && depth < 6; c = c.getCause(), depth++) {
            sb.append(depth == 0 ? "\n\n" : "\nCaused by: ").append(c.getClass().getName());
            if (c.getMessage() != null) sb.append(": ").append(c.getMessage());
            StackTraceElement[] st = c.getStackTrace();
            for (int i = 0; i < Math.min(st.length, 8); i++) sb.append("\n  at ").append(st[i]);
        }
        return sb.toString();
    }

    /** Version name without depending on the generated BuildConfig class. */
    static final class BuildConfigInfo {
        private static String cached;

        static String version() {
            return cached != null ? cached : "?";
        }

        static void init(Context ctx) {
            try {
                cached = ctx.getPackageManager().getPackageInfo(ctx.getPackageName(), 0).versionName;
            } catch (Throwable ignored) {
                cached = "?";
            }
        }
    }
}
