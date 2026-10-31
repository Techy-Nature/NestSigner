package io.github.techynature.nestsigner.core;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/** Minimal DER (ASN.1) encoder — just enough to build an X.509 certificate. */
final class Der {

    private Der() {}

    static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + 6);
        out.write(tag);
        int len = content.length;
        if (len < 0x80) {
            out.write(len);
        } else {
            int bytes = 0;
            for (int l = len; l > 0; l >>>= 8) bytes++;
            out.write(0x80 | bytes);
            for (int i = bytes - 1; i >= 0; i--) out.write((len >>> (8 * i)) & 0xFF);
        }
        out.write(content, 0, content.length);
        return out.toByteArray();
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.write(p, 0, p.length);
        return out.toByteArray();
    }

    static byte[] seq(byte[]... parts) { return tlv(0x30, concat(parts)); }

    static byte[] set(byte[]... parts) { return tlv(0x31, concat(parts)); }

    static byte[] integer(BigInteger v) { return tlv(0x02, v.toByteArray()); }

    static byte[] nul() { return new byte[] {0x05, 0x00}; }

    static byte[] utf8(String s) { return tlv(0x0C, s.getBytes(StandardCharsets.UTF_8)); }

    static byte[] printable(String s) { return tlv(0x13, s.getBytes(StandardCharsets.US_ASCII)); }

    static byte[] octetString(byte[] b) { return tlv(0x04, b); }

    static byte[] bitString(byte[] b) {
        byte[] c = new byte[b.length + 1];
        System.arraycopy(b, 0, c, 1, b.length); // 0 unused bits
        return tlv(0x03, c);
    }

    /** Context-specific, constructed, explicit tag [n]. */
    static byte[] explicit(int n, byte[] content) { return tlv(0xA0 | n, content); }

    static byte[] oid(String dotted) {
        String[] arcs = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBase128(out, Long.parseLong(arcs[0]) * 40 + Long.parseLong(arcs[1]));
        for (int i = 2; i < arcs.length; i++) writeBase128(out, Long.parseLong(arcs[i]));
        return tlv(0x06, out.toByteArray());
    }

    private static void writeBase128(ByteArrayOutputStream out, long v) {
        int groups = 1;
        for (long t = v >>> 7; t > 0; t >>>= 7) groups++;
        for (int i = groups - 1; i >= 0; i--) {
            int b = (int) ((v >>> (7 * i)) & 0x7F);
            out.write(i == 0 ? b : (b | 0x80));
        }
    }

    /** UTCTime for 1950–2049, GeneralizedTime otherwise (RFC 5280 §4.1.2.5). */
    static byte[] time(Date d) {
        Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.US);
        c.setTime(d);
        int year = c.get(Calendar.YEAR);
        boolean utc = year >= 1950 && year < 2050;
        SimpleDateFormat f = new SimpleDateFormat(utc ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'", Locale.US);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return tlv(utc ? 0x17 : 0x18, f.format(d).getBytes(StandardCharsets.US_ASCII));
    }
}
