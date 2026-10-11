// Minimal lenient HTTP/1.x request reader for the canary.
//
// The canary must show what Log4j does with ANY request an application server
// might hand it, so this parser deliberately takes the request target and the
// header names and values exactly as sent, and does not reject characters that
// a strict server (such as the JDK's HttpServer) would refuse with a 400.
// Pure JDK; no Log4j dependency, so it can be tested on its own.
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

final class RawHttp {
    static final class Req {
        String method = "";
        String target = "";
        String version = "";
        final List<String[]> headers = new ArrayList<>(); // {name, value}
        byte[] body = new byte[0];
    }

    private RawHttp() {}

    /** Returns null if the peer closed without sending anything. */
    static Req parse(InputStream in, int maxHeaderBytes, int maxBody) throws IOException {
        int[] budget = {maxHeaderBytes};
        String line = readLine(in, budget);
        if (line == null) return null;
        while (line.isEmpty()) { // tolerate leading blank lines
            line = readLine(in, budget);
            if (line == null) return null;
        }
        Req r = new Req();
        int a = line.indexOf(' ');
        int b = line.lastIndexOf(' ');
        if (a < 0) {
            r.method = line;
        } else {
            r.method = line.substring(0, a);
            if (b > a && line.substring(b + 1).startsWith("HTTP/")) {
                r.target = line.substring(a + 1, b);
                r.version = line.substring(b + 1);
            } else {
                r.target = line.substring(a + 1);
            }
        }
        int contentLength = 0;
        boolean chunked = false;
        for (;;) {
            String h = readLine(in, budget);
            if (h == null || h.isEmpty()) break;
            int c = h.indexOf(':');
            String name = c < 0 ? h : h.substring(0, c);
            String value = c < 0 ? "" : h.substring(c + 1).trim();
            r.headers.add(new String[] {name, value});
            String ln = name.trim().toLowerCase();
            if (ln.equals("content-length")) {
                try {
                    contentLength = Math.max(0, Integer.parseInt(value));
                } catch (NumberFormatException e) {
                    contentLength = 0;
                }
            } else if (ln.equals("transfer-encoding") && value.toLowerCase().contains("chunked")) {
                chunked = true;
            }
        }
        r.body = chunked ? readChunked(in, maxBody, budget) : readN(in, Math.min(contentLength, maxBody));
        return r;
    }

    private static byte[] readN(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int got = 0;
        while (got < n) {
            int k = in.read(buf, got, n - got);
            if (k < 0) break;
            got += k;
        }
        return got == n ? buf : java.util.Arrays.copyOf(buf, got);
    }

    private static byte[] readChunked(InputStream in, int max, int[] budget) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (;;) {
            String sz = readLine(in, budget);
            if (sz == null) break;
            int semi = sz.indexOf(';');
            if (semi >= 0) sz = sz.substring(0, semi);
            int n;
            try {
                n = Integer.parseInt(sz.trim(), 16);
            } catch (NumberFormatException e) {
                break;
            }
            if (n == 0) {
                while (true) { // trailers
                    String t = readLine(in, budget);
                    if (t == null || t.isEmpty()) break;
                }
                break;
            }
            byte[] chunk = readN(in, n);
            if (out.size() + chunk.length <= max) out.write(chunk, 0, chunk.length);
            readLine(in, budget); // CRLF after chunk data
        }
        return out.toByteArray();
    }

    /** Reads one line, bytes taken as ISO-8859-1 (as application servers do). */
    private static String readLine(InputStream in, int[] budget) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        boolean any = false;
        while ((c = in.read()) >= 0) {
            any = true;
            if (--budget[0] < 0) throw new IOException("header section too large");
            if (c == '\n') break;
            b.write(c);
        }
        if (!any) return null;
        byte[] raw = b.toByteArray();
        int n = raw.length;
        if (n > 0 && raw[n - 1] == '\r') n--;
        return new String(raw, 0, n, StandardCharsets.ISO_8859_1);
    }
}
