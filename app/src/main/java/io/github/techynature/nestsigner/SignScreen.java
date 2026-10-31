package io.github.techynature.nestsigner;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.provider.Settings;
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
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;

import io.github.techynature.nestsigner.core.ApkSigning;
import io.github.techynature.nestsigner.core.FolderPacker;
import io.github.techynature.nestsigner.core.KeystoreException;
import io.github.techynature.nestsigner.core.KeystoreLoader;

/**
 * The "Sign an APK" screen: pick an APK (or an unzipped APK folder) and a keystore,
 * unlock it, and save a packed, aligned and signed copy.
 */
final class SignScreen {

    static final int REQ_PICK_APK = 50;
    static final int REQ_PICK_KEYSTORE = 51;
    static final int REQ_SAVE_APK = 52;
    static final int REQ_PICK_FOLDER = 53;

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
    private final View accessGroup;

    // The input is either an APK/zip file (apkUri) or an unzipped APK folder (folderUri)
    private Uri apkUri;
    private Uri folderUri;
    private String inputName;
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
        accessGroup = find(R.id.sign_access_group);
        find(R.id.sign_access_button).setOnClickListener(v -> requestAllFilesAccess());

        find(R.id.sign_pick_apk).setOnClickListener(v -> pickApk());
        find(R.id.sign_pick_folder).setOnClickListener(v -> pickFolder());
        find(R.id.sign_pick_ks).setOnClickListener(v -> pickKeystore());
        unlockButton.setOnClickListener(v -> unlock());
        samePw.setOnCheckedChangeListener((b, checked) ->
                keyPwGroup.setVisibility(checked ? View.GONE : View.VISIBLE));
        signButton.setOnClickListener(v -> onSignClicked());
        find(R.id.sign_again_button).setOnClickListener(v -> {
            resultCard.setVisibility(View.GONE);
            signButton.setVisibility(View.VISIBLE);
            clearInput();
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

    /** Shows the "All files access" offer only when a folder is chosen and access isn't granted. */
    void refreshAccessOffer() {
        boolean offer = folderUri != null && Build.VERSION.SDK_INT >= 30 && !SafFolder.hasAllFilesAccess();
        accessGroup.setVisibility(offer ? View.VISIBLE : View.GONE);
    }

    private void requestAllFilesAccess() {
        if (Build.VERSION.SDK_INT < 30) return;
        try {
            activity.startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:" + activity.getPackageName())));
        } catch (Exception e) {
            try {
                activity.startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            } catch (Exception e2) {
                showError("Couldn't open the All files access setting on this device.");
            }
        }
    }

    private void clearInput() {
        apkUri = null;
        folderUri = null;
        inputName = null;
        apkName.setText(R.string.nothing_chosen);
        refreshAccessOffer();
    }

    // ---------- picking ----------

    private void pickApk() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        // Some file managers label APKs as zip or octet-stream
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_MIME_TYPES, new String[] {
                "application/vnd.android.package-archive", "application/zip", "application/octet-stream"});
        start(i, REQ_PICK_APK);
    }

    private void pickFolder() {
        start(new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), REQ_PICK_FOLDER);
    }

    private void pickKeystore() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        start(i, REQ_PICK_KEYSTORE);
    }

    private void start(Intent i, int request) {
        try {
            activity.startActivityForResult(i, request);
        } catch (Exception e) {
            showError("This device has no file picker.");
        }
    }

    /** Returns true if the request code belonged to this screen. */
    boolean handleResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != REQ_PICK_APK && requestCode != REQ_PICK_KEYSTORE
                && requestCode != REQ_SAVE_APK && requestCode != REQ_PICK_FOLDER) {
            return false;
        }
        if (resultCode != Activity.RESULT_OK || data == null || data.getData() == null) return true;
        Uri uri = data.getData();
        showError(null);
        if (requestCode == REQ_PICK_APK) {
            clearInput();
            apkUri = uri;
            inputName = displayName(uri, "app.apk");
            apkName.setText(inputName);
        } else if (requestCode == REQ_PICK_FOLDER) {
            clearInput();
            folderUri = uri;
            inputName = SafFolder.displayName(activity, uri);
            apkName.setText(activity.getString(R.string.folder_chosen, inputName));
            refreshAccessOffer();
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

    private String outputBaseName() {
        String base = inputName == null ? "app" : inputName;
        return base.replaceAll("(?i)\\.(apk|zip)$", "");
    }

    private void onSignClicked() {
        if (apkUri == null && folderUri == null) {
            showError("Choose an APK or an unzipped APK folder to sign.");
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

        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/vnd.android.package-archive");
        i.putExtra(Intent.EXTRA_TITLE, outputBaseName() + "-signed.apk");
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
        if ((apkUri == null && folderUri == null) || opened == null) {
            showError("Something changed while saving. Please try again.");
            return;
        }
        final Uri sourceFile = apkUri;
        final Uri sourceFolder = folderUri;
        final String alias = selectedAlias();
        final char[] kp = keyPassword();
        final KeystoreLoader.Opened ks = opened;

        setBusy(true, sourceFolder != null);
        new Thread(() -> {
            File dir = new File(activity.getCacheDir(), "signing");
            File in = new File(dir, "input.apk");
            File out = new File(dir, "output.apk");
            String step = "preparing";
            String error = null;
            Throwable problem = null;
            ApkSigning.Report report = null;
            int packed = -1;
            try {
                if (!dir.isDirectory() && !dir.mkdirs()) throw new IllegalStateException("No temp space.");
                if (sourceFolder != null) {
                    step = "reading the folder";
                    List<FolderPacker.Item> items = SafFolder.list(activity, sourceFolder);
                    step = "packing the folder";
                    packed = FolderPacker.pack(items, in, (done, total) -> main.post(() ->
                            signButton.setText(activity.getString(R.string.packing_progress, done, total))));
                } else {
                    step = "reading the APK";
                    copy(activity.getContentResolver().openInputStream(sourceFile), new FileOutputStream(in));
                }
                if (in.length() == 0) throw new IllegalStateException("The chosen file is empty.");
                step = "unlocking the key";
                KeystoreLoader.SigningKey key = ks.unlock(alias, kp);
                step = "signing";
                report = ApkSigning.sign(in, out, key, dir);
                step = "saving the signed APK";
                Ui.writeToDocument(activity, out, target);
            } catch (KeystoreException | ApkSigning.SignException | FolderPacker.PackException e) {
                error = e.getMessage();
                problem = e;
            } catch (Throwable t) {
                // Catch everything, including library errors, so a failure is never silent
                error = "Something went wrong while " + step + ".";
                problem = t;
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
                } catch (Throwable ignored) {
                    // the provider may not support deleting
                }
            }
            final String finalError = error;
            final Throwable finalProblem = problem;
            final ApkSigning.Report finalReport = report;
            final int finalPacked = packed;
            main.post(() -> {
                setBusy(false, false);
                if (finalError != null) {
                    showError(finalError);
                    Ui.showProblem(activity, "Signing failed", finalError, finalProblem);
                } else {
                    showResult(finalReport, alias, finalPacked);
                }
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

    private void setBusy(boolean busy, boolean packing) {
        signButton.setEnabled(!busy);
        signButton.setText(!busy ? R.string.sign : packing ? R.string.packing : R.string.signing);
    }

    private void showResult(ApkSigning.Report r, String alias, int packedFiles) {
        String from = "";
        if (packedFiles >= 0) {
            from = "\n(packed " + packedFiles + " files from the folder " + inputName + ")";
        } else if (r.extractedFrom != null) {
            from = "\n(unpacked " + r.extractedFrom + " from the zip you chose)";
        }
        resultText.setText("File: " + outputBaseName() + "-signed.apk"
                + from
                + "\nKey: " + alias
                + "\nAligned: yes"
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
