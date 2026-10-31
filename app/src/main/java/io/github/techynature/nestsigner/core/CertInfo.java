package io.github.techynature.nestsigner.core;

import java.util.Locale;

/** The "who is this certificate for" fields. Only the name is required. */
public final class CertInfo {
    public final String commonName;
    public final String orgUnit;
    public final String organization;
    public final String city;
    public final String state;
    public final String countryCode;

    public CertInfo(String commonName, String orgUnit, String organization,
                    String city, String state, String countryCode) {
        this.commonName = clean(commonName);
        this.orgUnit = clean(orgUnit);
        this.organization = clean(organization);
        this.city = clean(city);
        this.state = clean(state);
        String cc = clean(countryCode);
        this.countryCode = cc.toUpperCase(Locale.US);
    }

    private static String clean(String s) {
        return s == null ? "" : s.trim();
    }

    /** Returns an error message, or null if everything is valid. */
    public String validate() {
        if (commonName.isEmpty()) return "Enter your name or your organization's name.";
        String[][] fields = {
                {"Name", commonName}, {"Team / unit", orgUnit}, {"Organization", organization},
                {"City", city}, {"State / region", state}
        };
        for (String[] f : fields) {
            if (f[1].length() > 64) return f[0] + " must be 64 characters or fewer.";
        }
        if (!countryCode.isEmpty() && !countryCode.matches("[A-Z]{2}")) {
            return "Country code must be two letters, like US or CA.";
        }
        return null;
    }

    /** Human-readable form, e.g. "CN=Nest, O=Techy Nature, C=US". */
    public String toDisplayString() {
        StringBuilder sb = new StringBuilder("CN=").append(commonName);
        if (!orgUnit.isEmpty()) sb.append(", OU=").append(orgUnit);
        if (!organization.isEmpty()) sb.append(", O=").append(organization);
        if (!city.isEmpty()) sb.append(", L=").append(city);
        if (!state.isEmpty()) sb.append(", ST=").append(state);
        if (!countryCode.isEmpty()) sb.append(", C=").append(countryCode);
        return sb.toString();
    }
}
