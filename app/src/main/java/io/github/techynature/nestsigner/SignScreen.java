package io.github.techynature.nestsigner;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import io.github.techynature.nestsigner.core.ApkSigning;
import io.github.techynature.nestsigner.core.KeystoreException;
import io.github.techynature.nestsigner.core.KeystoreLoader;

/** The "Sign an APK" screen: pick an APK and a keystore, unlock it, save a signed copy. */
final class SignScreen {

    static final int REQ_PICK_APK = 50;
    static final int REQ_PICK_KEYSTORE = 51;
    static final int REQ_SAVE_APK = 52;

    private static final int MAX_KEYSTORE_BYTES = 1024 * 1024;

    private final Activity activity;
    private final ScrollView root;
    private final Handler main = new Handler(Looper.getMainLooper());

    private final TextView apkName, keystoreName, errorText, resultText;
    private final EditText storePw, keyPw;
    private final Button unlockButton, signButton;
    private final View unlockedGroup, keyPwGroup, resultCard;
    private final Spinner aliasSpinner;
    private final TextView aliasSingle;
    private final CheckBox samePw;

    private Uri apkUri;
    private String apkDisplayName;
    private byte[] keystoreBytes;
    private KeystoreLoader.Opened opened;

    SignScreen(Activity activity, ScrollView root) {
        this.activity = activity;
        this.root = root;
        apkName = find(R.id.sign_apk_name);
        keystoreName = find(R.id.sign_ks_name);
        storePw = find(R.id.sign_store_pw);
        unlockButton = find(R.id.sign_unlock_button);
        unlockedGroup = find(R.id.sign_unlocked_group);
        aliasSpinner = find(R.id.sign_alias_spinner);
        aliasSingle = find(R.id.sign_alias_single);
        samePw = find(R.id.sign_same_pw);
        keyPwGroup = find(R.id.sign_key_pw_group);
        keyPw = find(R.id.sign_key_pw);
        errorText = find(R.id.sign_error_text);
        signButton = find(R.id.sign_button);
        resultCard = find(R.id.sign_result_card);
        resultText = find(R.id.sign_result_text);

        find(R.id.sign_pick_apk).setOnClickListener(v -> pick(REQ_PICK_APK, "application/vnd.android.package-archive"));
        find(R.id.sign_pick_ks).setOnClickListener(v -> pick(REQ_PICK_KEYSTORE, "*/*"));
        unlockButton.setOnClickListener(v -> unlock());
        samePw.setOnCheckedChangeListener((b, checked) ->
                keyPwGroup.setVisibility(checked ? View.GONE : View.VISIBLE));
        signButton.setOnClickListener(v -> onSignClicked());
        find(R.id.sign_again_button).setOnClickListener(v -> {
            resultCard.setVisibility(View.GONE);
            signButton.setVisibility(View.VISIBLE);
            apkUri = null;
            apkDisplayName = null;
            apkName.setText(R.string.nothing_chosen);
            root.smoothScrollTo(0, 0);
        });
    }

    @SuppressWarnings("unchecked")
    private <T extends View> T find(int id) {
        return (T) activity.findViewById(id);
    }

    EditText[] passwordFields() {
        return new EditText[] {storePw, keyPw};
    }

    // ---------- picking ----------

    private void pick(int request, String mime) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType(mime);
        if (request == REQ_PICK_APK) {
            // Some file managers label APKs as zip or octet-stream
            i.setType("*/*");
            i.putExtra(Intent.EXTRA_MIME_TYPES, new String[] {
                    "application/vnd.android.package-archive", "application/zip", "application/octet-stream"});
        }
        try {
            activity.startActivityForResult(i, request);
        } catch (Exception e) {
            showError("This device has no file picker.");
        }
    }

    /** Returns true if the request code belonged to this screen. */
    boolean handleResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != REQ_PICK_APK && requestCode != REQ_PICK_KEYSTORE && requestCode != REQ_SAVE_APK) {
            return false;
        }
        if (resultCode != Activity.RESULT_OK || data == null || data.getData() == null) return true;
        Uri uri = data.getData();
        showError(null);
        if (requestCode == REQ_PICK_APK) {
            apkUri = uri;
            apkDisplayName = displayName(uri, "app.apk");
            apkName.setText(apkDisplayName);
        } else if (requestCode == REQ_PICK_KEYSTORE) {
            loadKeystoreFile(uri);
        } else {
            signTo(uri);
        }
        return true;
    }

    private void loadKeystoreFile(Uri uri) {
        try (InputStream in = activity.getContentResolver().openInputStream(uri)) {
            if (in == null) throw new IllegalStateException();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) > 0) {
                buf.write(chunk, 0, n);
                if (buf.size() > MAX_KEYSTORE_BYTES) {
                    showError("That file is too big to be a keystore.");
                    return;
                }
            }
            keystoreBytes = buf.toByteArray();
            keystoreName.setText(displayName(uri, "keystore"));
            lock();
        } catch (Exception e) {
            showError("Couldn't read that file.");
        }
    }

    private String displayName(Uri uri, String fallback) {
        try (Cursor c = activity.getContentResolver().query(
                uri, new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                String name = c.getString(0);
                if (name != null && !name.isEmpty()) return name;
            }
        } catch (Exception ignored) {
            // fall through
        }
        return fallback;
    }

    // ---------- unlocking ----------

    private void lock() {
        opened = null;
        unlockedGroup.setVisibility(View.GONE);
        unlockButton.setVisibility(View.VISIBLE);
        unlockButton.setText(R.string.unlock);
    }

    private void unlock() {
        if (keystoreBytes == null) {
            showError("Choose a keystore file first.");
            return;
        }
        char[] pw = storePw.getText().toString().toCharArray();
        try {
            opened = KeystoreLoader.open(keystoreBytes, pw);
        } catch (KeystoreException e) {
            opened = null;
            showError(e.getMessage());
            return;
        } finally {
            Arrays.fill(pw, '\0');
        }
        showError(null);

        if (opened.aliases.size() == 1) {
            aliasSingle.setText(opened.aliases.get(0));
            aliasSingle.setVisibility(View.VISIBLE);
            ((View) aliasSpinner.getParent()).setVisibility(View.GONE);
        } else {
            ArrayAdapter<String> adapter = new ArrayAdapter<>(
                    activity, android.R.layout.simple_spinner_item, opened.aliases);
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            aliasSpinner.setAdapter(adapter);
            aliasSingle.setVisibility(View.GONE);
            ((View) aliasSpinner.getParent()).setVisibility(View.VISIBLE);
        }
        unlockedGroup.setVisibility(View.VISIBLE);
        unlockButton.setVisibility(View.GONE);
        Toast.makeText(activity, opened.type + " keystore unlocked", Toast.LENGTH_SHORT).show();
    }

    private String selectedAlias() {
        if (opened == null) return null;
        if (opened.aliases.size() == 1) return opened.aliases.get(0);
        Object sel = aliasSpinner.getSelectedItem();
        return sel == null ? null : sel.toString();
    }

    // ---------- signing ----------

    private void onSignClicked() {
        if (apkUri == null) {
            showError("Choose an APK to sign.");
            return;
        }
        if (opened == null) {
            showError(keystoreBytes == null ? "Choose a keystore file." : "Unlock the keystore first.");
            return;
        }
        // Check the key password now, before asking where to save
        try {
            opened.unlock(selectedAlias(), keyPassword());
        } catch (KeystoreException e) {
            showError(e.getMessage());
            return;
        }
        showError(null);

        String base = apkDisplayName == null ? "app" : apkDisplayName;
        if (base.toLowerCase().endsWith(".apk")) base = base.substring(0, base.length() - 4);
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/vnd.android.package-archive");
        i.putExtra(Intent.EXTRA_TITLE, base + "-signed.apk");
        try {
            activity.startActivityForResult(i, REQ_SAVE_APK);
        } catch (Exception e) {
            showError("This device has no file picker to save with.");
        }
    }

    private char[] keyPassword() {
        return (samePw.isChecked() ? storePw : keyPw).getText().toString().toCharArray();
    }

    private void signTo(Uri target) {
        if (apkUri == null || opened == null) {
            showError("Something changed while saving. Please try again.");
            return;
        }
        final Uri source = apkUri;
        final String alias = selectedAlias();
        final char[] kp = keyPassword();
        final KeystoreLoader.Opened ks = opened;

        setBusy(true);
        new Thread(() -> {
            File dir = new File(activity.getCacheDir(), "signing");
            File in = new File(dir, "input.apk");
            File out = new File(dir, "output.apk");
            String error = null;
            ApkSigning.Report report = null;
            try {
                if (!dir.isDirectory() && !dir.mkdirs()) throw new IllegalStateException("No temp space.");
                copy(activity.getContentResolver().openInputStream(source), new FileOutputStream(in));
                KeystoreLoader.SigningKey key = ks.unlock(alias, kp);
                report = ApkSigning.sign(in, out, key);
                copy(new FileInputStream(out), activity.getContentResolver().openOutputStream(target, "wt"));
            } catch (KeystoreException | ApkSigning.SignException e) {
                error = e.getMessage();
            } catch (Exception e) {
                error = "Something went wrong: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
            } finally {
                Arrays.fill(kp, '\0');
                //noinspection ResultOfMethodCallIgnored
                in.delete();
                //noinspection ResultOfMethodCallIgnored
                out.delete();
            }
            if (error != null) {
                try {
                    DocumentsContract.deleteDocument(activity.getContentResolver(), target);
                } catch (Exception ignored) {
                    // the provider may not support deleting
                }
            }
            final String finalError = error;
            final ApkSigning.Report finalReport = report;
            main.post(() -> {
                setBusy(false);
                if (finalError != null) showError(finalError);
                else showResult(finalReport, alias);
            });
        }, "nestsigner-sign").start();
    }

    private static void copy(InputStream in, OutputStream out) throws Exception {
        if (in == null || out == null) throw new IllegalStateException("Couldn't open the file.");
        try (InputStream i = in; OutputStream o = out) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = i.read(buf)) > 0) o.write(buf, 0, n);
        }
    }

    private void setBusy(boolean busy) {
        signButton.setEnabled(!busy);
        signButton.setText(busy ? R.string.signing : R.string.sign);
    }

    private void showResult(ApkSigning.Report r, String alias) {
        String base = apkDisplayName == null ? "app" : apkDisplayName.replaceAll("(?i)\\.apk$", "");
        resultText.setText("File: " + base + "-signed.apk"
                + "\nKey: " + alias
                + "\nSigned with: " + r.schemes()
                + "\nSigner: " + r.signer
                + "\n\nCertificate SHA-256:\n" + r.certSha256);
        signButton.setVisibility(View.GONE);
        resultCard.setVisibility(View.VISIBLE);
        Ui.scrollTo(root, resultCard);
    }

    private void showError(String msg) {
        errorText.setText(msg);
        errorText.setVisibility(msg == null ? View.GONE : View.VISIBLE);
        if (msg != null) Ui.scrollTo(root, errorText);
    }
}
