package io.github.techynature.nestsigner;

import android.text.InputType;
import android.view.View;
import android.view.ViewParent;
import android.widget.EditText;
import android.widget.ScrollView;

/** Small view helpers shared by both screens. */
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
}
