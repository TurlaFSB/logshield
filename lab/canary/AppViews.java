// What a typical application stack hands to its logger.
//
// Log4j itself never decodes percent-encoding, base64, charsets or gzip, but the
// frameworks around it do, and applications routinely log decoded values (the
// Basic-auth user name is the classic Log4Shell vector). This class derives the
// views a mainstream stack would produce from a raw request, so the canary can
// log them and the lab can tell which encodings are reachable in practice.
//
// Deliberately NOT modelled (frameworks do not do these by default): HTML
// entities, backslash escapes, full-width forms, overlong UTF-8, repeated
// percent-decoding, base64 inside base64.
//
// Pure JDK 8; no Log4j dependency.
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

final class AppViews {
    private static final int MAX = 65536;

    private AppViews() {}

    /** Returns {source, value} pairs. Never throws. */
    static List<String[]> of(RawHttp.Req req) {
        List<String[]> out = new ArrayList<>();
        try {
            derive(req, out);
        } catch (RuntimeException e) {
            // a decoder failing is what a framework would also do: no view
        }
        return out;
    }

    private static void derive(RawHttp.Req req, List<String[]> out) {
        String ct = header(req, "content-type");
        String ctl = ct.toLowerCase();
        String ce = header(req, "content-encoding").toLowerCase();
        byte[] body = req.body;

        // Content-Encoding handled by a decompression filter.
        if (body.length > 0 && (ce.contains("gzip") || ce.contains("deflate"))) {
            byte[] inflated = inflate(body, ce.contains("gzip"));
            if (inflated != null) {
                out.add(new String[] {"body.decompressed", utf8(inflated)});
                body = inflated;
            }
        }

        if (body.length > 0) {
            // Declared charset.
            String cs = param(ct, "charset");
            if (cs != null && !cs.equalsIgnoreCase("utf-8")) {
                String d = decode(body, cs);
                if (d != null) out.add(new String[] {"body.charset:" + cs, d});
            }
            // Charset sniffing, as JSON parsers do (RFC 4627 section 3).
            String sniff = sniffCharset(body);
            if (sniff != null) {
                String d = decode(body, sniff);
                if (d != null) out.add(new String[] {"body.sniffed:" + sniff, d});
            }
            // JSON string escapes.
            String text = utf8(body);
            if (ctl.contains("json") || text.startsWith("{") || text.startsWith("[")) {
                out.add(new String[] {"body.json-unescaped", jsonUnescape(text)});
            }
            // Form bodies.
            if (ctl.contains("application/x-www-form-urlencoded")) {
                for (String pair : text.split("&")) {
                    int eq = pair.indexOf('=');
                    String n = eq < 0 ? pair : pair.substring(0, eq);
                    String v = eq < 0 ? "" : pair.substring(eq + 1);
                    out.add(new String[] {"form-name", urldec(n)});
                    out.add(new String[] {"form:" + urldec(n), urldec(v)});
                }
            }
            // Multipart.
            String boundary = param(ct, "boundary");
            if (ctl.contains("multipart/") && boundary != null) {
                multipart(body, boundary, out);
            }
        }

        // Cookies.
        for (String[] h : req.headers) {
            if (h[0].trim().equalsIgnoreCase("cookie")) {
                for (String c : h[1].split(";")) {
                    int eq = c.indexOf('=');
                    if (eq < 0) continue;
                    out.add(new String[] {"cookie-name", urldec(c.substring(0, eq).trim())});
                    out.add(new String[] {"cookie:" + c.substring(0, eq).trim(), urldec(c.substring(eq + 1).trim())});
                }
            }
        }

        // Authorization.
        String auth = header(req, "authorization").trim();
        if (auth.regionMatches(true, 0, "Basic ", 0, 6)) {
            String d = b64(auth.substring(6).trim());
            if (d != null) {
                // Some stacks and gateways log the whole decoded credential.
                out.add(new String[] {"basic-decoded", d});
                // Servers split at the first colon, which a JNDI payload also contains.
                int colon = d.indexOf(':');
                out.add(new String[] {"basic-user", colon < 0 ? d : d.substring(0, colon)});
                if (colon >= 0) out.add(new String[] {"basic-password", d.substring(colon + 1)});
            }
        } else if (auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String[] seg = auth.substring(7).trim().split("\\.");
            for (int i = 0; i < seg.length && i < 2; i++) {
                String d = b64(seg[i]);
                if (d != null) out.add(new String[] {"jwt-segment-" + i, jsonUnescape(d)});
            }
        }
    }

    private static void multipart(byte[] body, String boundary, List<String[]> out) {
        String text = new String(body, StandardCharsets.ISO_8859_1);
        String delim = "--" + boundary;
        int from = 0;
        for (;;) {
            int s = text.indexOf(delim, from);
            if (s < 0) break;
            int next = text.indexOf(delim, s + delim.length());
            if (next < 0) break;
            String part = text.substring(s + delim.length(), next);
            if (part.startsWith("\r\n")) part = part.substring(2);
            int split = part.indexOf("\r\n\r\n");
            if (split >= 0) {
                String heads = part.substring(0, split);
                String content = part.substring(split + 4);
                if (content.endsWith("\r\n")) content = content.substring(0, content.length() - 2);
                String name = null;
                String filename = null;
                String pcs = null;
                for (String line : heads.split("\r\n")) {
                    String l = line.toLowerCase();
                    if (l.startsWith("content-disposition")) {
                        name = param(line, "name");
                        filename = param(line, "filename");
                    } else if (l.startsWith("content-type")) {
                        pcs = param(line, "charset");
                    }
                }
                byte[] raw = content.getBytes(StandardCharsets.ISO_8859_1);
                String v = pcs != null ? decode(raw, pcs) : utf8(raw);
                if (name != null) out.add(new String[] {"multipart-name", name});
                if (filename != null) out.add(new String[] {"multipart-filename", filename});
                if (v != null) out.add(new String[] {"multipart:" + (name == null ? "" : name), v});
            }
            from = next;
        }
    }

    private static String header(RawHttp.Req req, String name) {
        for (String[] h : req.headers) {
            if (h[0].trim().equalsIgnoreCase(name)) return h[1];
        }
        return "";
    }

    /** Value of ; key=value (quotes removed) or null. */
    static String param(String s, String key) {
        String lower = s.toLowerCase();
        int i = 0;
        while ((i = lower.indexOf(key + "=", i)) >= 0) {
            boolean boundary = i == 0 || !Character.isLetterOrDigit(lower.charAt(i - 1));
            if (boundary) {
                int st = i + key.length() + 1;
                int en = st;
                if (st < s.length() && s.charAt(st) == '"') {
                    en = s.indexOf('"', st + 1);
                    return en < 0 ? s.substring(st + 1) : s.substring(st + 1, en);
                }
                while (en < s.length() && s.charAt(en) != ';' && s.charAt(en) != ',') en++;
                return s.substring(st, en).trim();
            }
            i += key.length();
        }
        return null;
    }

    private static String decode(byte[] b, String charset) {
        try {
            return new String(b, Charset.forName(charset));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String sniffCharset(byte[] b) {
        if (b.length >= 4) {
            if ((b[0] & 0xff) == 0xFF && (b[1] & 0xff) == 0xFE) return b[2] == 0 && b[3] == 0 ? "UTF-32LE" : "UTF-16LE";
            if ((b[0] & 0xff) == 0xFE && (b[1] & 0xff) == 0xFF) return "UTF-16BE";
            if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] != 0) return "UTF-32BE";
            if (b[0] != 0 && b[1] == 0 && b[2] == 0 && b[3] == 0) return "UTF-32LE";
            if (b[0] == 0 && b[1] != 0 && b[2] == 0) return "UTF-16BE";
            if (b[0] != 0 && b[1] == 0 && b[2] != 0 && b[3] == 0) return "UTF-16LE";
        }
        return null;
    }

    private static byte[] inflate(byte[] b, boolean gzip) {
        try (InputStream in = gzip ? new GZIPInputStream(new ByteArrayInputStream(b))
                                   : new InflaterInputStream(new ByteArrayInputStream(b))) {
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                if (o.size() + n > MAX) break;
                o.write(buf, 0, n);
            }
            return o.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    private static String b64(String s) {
        try {
            return utf8(Base64.getMimeDecoder().decode(s.replace('-', '+').replace('_', '/')));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String urldec(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    /** Decodes JSON string escapes (backslash-u, \n, \" ...) anywhere in s. */
    static String jsonUnescape(String s) {
        StringBuilder o = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                o.append(c);
                continue;
            }
            char n = s.charAt(++i);
            switch (n) {
                case 'n': o.append('\n'); break;
                case 't': o.append('\t'); break;
                case 'r': o.append('\r'); break;
                case 'b': o.append('\b'); break;
                case 'f': o.append('\f'); break;
                case '/': o.append('/'); break;
                case '\\': o.append('\\'); break;
                case '"': o.append('"'); break;
                case 'u':
                    if (i + 4 < s.length()) {
                        try {
                            o.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                            i += 4;
                            break;
                        } catch (NumberFormatException e) {
                            // fall through: keep as written
                        }
                    }
                    o.append("\\u");
                    break;
                default: o.append('\\').append(n);
            }
        }
        return o.toString();
    }
}
