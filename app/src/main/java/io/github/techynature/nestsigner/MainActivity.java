package io.github.techynature.nestsigner;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.text.InputType;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.OutputStream;
import java.text.DateFormat;
import java.util.Arrays;

import io.github.techynature.nestsigner.core.CertInfo;
import io.github.techynature.nestsigner.core.KeystoreFactory;

public class MainActivity extends Activity {

    private static final int REQ_SAVE = 42;
    private static final int MIN_PASSWORD = 6;

    private ScrollView root;
    private EditText fileName, storePw, storePw2, alias, keyPw, keyPw2;
    private EditText cn, ou, org, city, state, country, years;
    private CheckBox samePw, showPw;
    private View keyPwGroup, resultCard;
    private TextView errorText, resultText;
    private Button createButton;

    private final Handler main = new Handler(Looper.getMainLooper());
    private String lastDetails = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        root = findViewById(R.id.root);
        fileName = findViewById(R.id.file_name);
        storePw = findViewById(R.id.store_pw);
        storePw2 = findViewById(R.id.store_pw2);
        alias = findViewById(R.id.alias);
        samePw = findViewById(R.id.same_pw);
        keyPwGroup = findViewById(R.id.key_pw_group);
        keyPw = findViewById(R.id.key_pw);
        keyPw2 = findViewById(R.id.key_pw2);
        showPw = findViewById(R.id.show_pw);
        cn = findViewById(R.id.cn);
        ou = findViewById(R.id.ou);
        org = findViewById(R.id.org);
        city = findViewById(R.id.city);
        state = findViewById(R.id.state);
        country = findViewById(R.id.country);
        years = findViewById(R.id.years);
        errorText = findViewById(R.id.error_text);
        createButton = findViewById(R.id.create_button);
        resultCard = findViewById(R.id.result_card);
        resultText = findViewById(R.id.result_text);

        applyInsets();

        samePw.setOnCheckedChangeListener((b, checked) ->
                keyPwGroup.setVisibility(checked ? View.GONE : View.VISIBLE));
        keyPwGroup.setVisibility(samePw.isChecked() ? View.GONE : View.VISIBLE);

        showPw.setOnCheckedChangeListener((b, checked) -> setPasswordsVisible(checked));

        createButton.setOnClickListener(v -> onCreateClicked());
        findViewById(R.id.copy_button).setOnClickListener(v -> copyDetails());
        findViewById(R.id.again_button).setOnClickListener(v -> {
            resultCard.setVisibility(View.GONE);
            createButton.setVisibility(View.VISIBLE);
            root.smoothScrollTo(0, 0);
        });
    }

    /** Keeps content clear of the status bar, nav bar and keyboard (Android 15 draws edge-to-edge). */
    private void applyInsets() {
        final int base = root.getPaddingTop();
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            int top, bottom, left, right;
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.ime() | WindowInsets.Type.displayCutout());
                top = bars.top; bottom = bars.bottom; left = bars.left; right = bars.right;
            } else {
                top = insets.getSystemWindowInsetTop();
                bottom = insets.getSystemWindowInsetBottom();
                left = insets.getSystemWindowInsetLeft();
                right = insets.getSystemWindowInsetRight();
            }
            v.setPadding(left, base + top, right, base + bottom);
            return insets;
        });
    }

    private void setPasswordsVisible(boolean visible) {
        int type = InputType.TYPE_CLASS_TEXT | (visible
                ? InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                : InputType.TYPE_TEXT_VARIATION_PASSWORD);
        for (EditText e : new EditText[] {storePw, storePw2, keyPw, keyPw2}) {
            int sel = e.getSelectionEnd();
            e.setInputType(type);
            e.setSelection(Math.max(0, sel));
        }
    }

    // ---------- validation ----------

    private String validate() {
        String name = cleanFileName();
        if (name.isEmpty()) return "Enter a file name for the keystore.";

        String pwError = checkPasswords(storePw, storePw2, "Keystore password");
        if (pwError != null) return pwError;

        String aliasError = KeystoreFactory.validateAlias(alias.getText().toString());
        if (aliasError != null) return aliasError;

        if (!samePw.isChecked()) {
            pwError = checkPasswords(keyPw, keyPw2, "Key password");
            if (pwError != null) return pwError;
        }

        String certError = certInfo().validate();
        if (certError != null) return certError;

        int y = validityYears();
        if (y < 1 || y > 100) return "Validity must be between 1 and 100 years.";
        return null;
    }

    private static String checkPasswords(EditText a, EditText b, String label) {
        String p1 = a.getText().toString();
        String p2 = b.getText().toString();
        if (p1.length() < MIN_PASSWORD) return label + " must be at least " + MIN_PASSWORD + " characters.";
        if (!p1.equals(p2)) return label + "s don't match.";
        return null;
    }

    private String cleanFileName() {
        String n = fileName.getText().toString().trim();
        if (n.toLowerCase().endsWith(".jks")) n = n.substring(0, n.length() - 4);
        return n.replaceAll("[\\\\/:*?\"<>|\\s]+", "-");
    }

    private CertInfo certInfo() {
        return new CertInfo(text(cn), text(ou), text(org), text(city), text(state), text(country));
    }

    private int validityYears() {
        try {
            return Integer.parseInt(text(years));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static String text(EditText e) {
        return e.getText().toString().trim();
    }

    private void showError(String msg) {
        errorText.setText(msg);
        errorText.setVisibility(msg == null ? View.GONE : View.VISIBLE);
        if (msg != null) root.post(() -> root.smoothScrollTo(0, errorText.getTop()));
    }

    // ---------- create + save ----------

    private void onCreateClicked() {
        String err = validate();
        showError(err);
        if (err != null) return;

        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/octet-stream");
        i.putExtra(Intent.EXTRA_TITLE, cleanFileName() + ".jks");
        try {
            startActivityForResult(i, REQ_SAVE);
        } catch (Exception e) {
            showError("This device has no file picker to save with.");
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_SAVE) return;
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            Toast.makeText(this, "Save cancelled", Toast.LENGTH_SHORT).show();
            return;
        }
        // Re-check in case the screen was rebuilt while the picker was open
        String err = validate();
        if (err != null) {
            showError(err);
            return;
        }
        generateAndSave(data.getData());
    }

    private void generateAndSave(Uri target) {
        final String aliasText = alias.getText().toString();
        final char[] store = storePw.getText().toString().toCharArray();
        final char[] key = samePw.isChecked() ? store.clone() : keyPw.getText().toString().toCharArray();
        final CertInfo info = certInfo();
        final int y = validityYears();
        final String shownName = cleanFileName() + ".jks";

        setBusy(true);
        new Thread(() -> {
            String error = null;
            KeystoreFactory.Result result = null;
            try {
                result = KeystoreFactory.create(aliasText, store, key, info, y);
                try (OutputStream out = getContentResolver().openOutputStream(target, "wt")) {
                    if (out == null) throw new IllegalStateException("Couldn't open the file for writing.");
                    out.write(result.jksBytes);
                }
            } catch (Exception e) {
                error = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                try {
                    DocumentsContract.deleteDocument(getContentResolver(), target);
                } catch (Exception ignored) {
                    // leave it; the picker's provider may not support deleting
                }
            } finally {
                Arrays.fill(store, '\0');
                Arrays.fill(key, '\0');
            }
            final String finalError = error;
            final KeystoreFactory.Result finalResult = result;
            main.post(() -> {
                setBusy(false);
                if (finalError != null) {
                    showError("Something went wrong: " + finalError);
                } else {
                    showResult(finalResult, shownName);
                }
            });
        }, "nestsigner-generate").start();
    }

    private void setBusy(boolean busy) {
        createButton.setEnabled(!busy);
        createButton.setText(busy ? R.string.creating : R.string.create);
    }

    private void showResult(KeystoreFactory.Result r, String shownName) {
        String until = DateFormat.getDateInstance(DateFormat.LONG).format(r.notAfter);
        lastDetails = "File: " + shownName
                + "\nAlias: " + r.alias
                + "\nKey: RSA " + KeystoreFactory.KEY_SIZE + "-bit"
                + "\nCertificate: " + r.subject
                + "\nValid until: " + until
                + "\n\nSHA-1:\n" + r.sha1
                + "\n\nSHA-256:\n" + r.sha256;
        resultText.setText(lastDetails);

        // Passwords are no longer needed on screen
        for (EditText e : new EditText[] {storePw, storePw2, keyPw, keyPw2}) e.setText("");

        createButton.setVisibility(View.GONE);
        resultCard.setVisibility(View.VISIBLE);
        root.post(() -> root.smoothScrollTo(0, resultCard.getTop()));
    }

    private void copyDetails() {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("Keystore details", lastDetails));
            if (Build.VERSION.SDK_INT < 33) Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
        }
    }
}
