package io.github.techynature.nestsigner.core;

/** A keystore problem with a message that's safe to show to the user as-is. */
public final class KeystoreException extends Exception {

    public enum Reason { WRONG_STORE_PASSWORD, WRONG_KEY_PASSWORD, UNSUPPORTED, CORRUPT, NO_KEYS }

    public final Reason reason;

    public KeystoreException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public KeystoreException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }
}
