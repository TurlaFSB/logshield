// Echo backend (JDK com.sun.net.httpserver). Replies with what it received, as JSON.
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

public class Echo {
    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20 || c > 0x7e) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    public static void main(String[] a) throws Exception {
        AtomicInteger seq = new AtomicInteger();
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", Integer.parseInt(System.getenv("PORT"))), 0);
        s.createContext("/", ex -> {
            byte[] body = ex.getRequestBody().readAllBytes();
            StringBuilder h = new StringBuilder("[");
            boolean first = true;
            for (var e : ex.getRequestHeaders().entrySet())
                for (String v : e.getValue()) {
                    if (!first) h.append(',');
                    first = false;
                    h.append(q(e.getKey())).append(',').append(q(v));
                }
            h.append(']');
            String out = "{\"seq\":" + seq.incrementAndGet() + ",\"method\":" + q(ex.getRequestMethod())
                + ",\"target\":" + q(ex.getRequestURI().getRawPath() + (ex.getRequestURI().getRawQuery() != null ? "?" + ex.getRequestURI().getRawQuery() : ""))
                + ",\"version\":" + q(ex.getProtocol()) + ",\"headers\":" + h
                + ",\"body\":" + q(new String(body, StandardCharsets.ISO_8859_1)) + "}";
            byte[] o = out.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, o.length);
            ex.getResponseBody().write(o);
            ex.close();
        });
        s.start();
    }
}
