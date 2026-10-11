// Canary: a deliberately vulnerable Log4j 2.14.1 application used ONLY as an
// oracle in the LogShield lab. It logs every part of every request through
// real Log4j and reports what Log4j actually rendered, so the lab can compare
// "what the engine decided" with "what a vulnerable Log4j really did".
//
// Run it only on the isolated lab network. Never expose it anywhere else.
//
// JNDI oracle: run with -Djava.naming.factory.url.pkgs=lab.jndi for the hermetic
// recording hook (no network), or without it to let lookups reach the network.
//
// Env: CANARY_PORT (default 8080), CANARY_ADDR (default 127.0.0.1),
//      CANARY_MAX_BODY (default 65536).
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lab.jndi.Hook;
import java.util.concurrent.Executors;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.WriterAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.layout.PatternLayout;

public final class Canary {
    private static final StringWriter CAPTURE = new StringWriter();
    private static final Object LOCK = new Object();
    private static Logger log;
    private static WriterAppender appender;
    private static int maxBody = 65536;

    public static void main(String[] args) throws Exception {
        // Bound how long a triggered JNDI lookup can hang the worker.
        System.setProperty("com.sun.jndi.ldap.connect.timeout", "2000");
        System.setProperty("com.sun.jndi.ldap.read.timeout", "2000");

        String portS = System.getenv().getOrDefault("CANARY_PORT", "8080");
        String addr = System.getenv().getOrDefault("CANARY_ADDR", "127.0.0.1");
        maxBody = Integer.parseInt(System.getenv().getOrDefault("CANARY_MAX_BODY", "65536"));

        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration cfg = ctx.getConfiguration();
        PatternLayout layout = PatternLayout.newBuilder().withPattern("%m").withConfiguration(cfg).build();
        appender = WriterAppender.newBuilder().setName("capture").setTarget(CAPTURE).setLayout(layout).build();
        appender.start();
        cfg.addAppender(appender);
        cfg.getRootLogger().addAppender(appender, Level.INFO, null);
        ctx.updateLoggers();
        log = LogManager.getLogger("canary");

        HttpServer srv = HttpServer.create(new InetSocketAddress(addr, Integer.parseInt(portS)), 128);
        srv.setExecutor(Executors.newFixedThreadPool(8));
        srv.createContext("/", Canary::handle);
        srv.start();
        System.out.println("canary listening on " + addr + ":" + portS + " (log4j-core 2.14.1, lookups ON)");
    }

    private static void handle(HttpExchange ex) throws IOException {
        List<String[]> items = new ArrayList<>(); // {source, raw}
        String rawUri = ex.getRequestURI().getRawPath();
        String rawQuery = ex.getRequestURI().getRawQuery();
        items.add(new String[] {"path", rawUri});
        items.add(new String[] {"path.decoded", dec(rawUri)});
        if (rawQuery != null) {
            items.add(new String[] {"query", rawQuery});
            items.add(new String[] {"query.decoded", dec(rawQuery)});
        }
        for (Map.Entry<String, List<String>> h : ex.getRequestHeaders().entrySet()) {
            for (String v : h.getValue()) {
                items.add(new String[] {"header:" + h.getKey(), v});
            }
        }
        byte[] body = readBounded(ex.getRequestBody(), maxBody);
        if (body.length > 0) {
            String b = new String(body, StandardCharsets.UTF_8);
            items.add(new String[] {"body", b});
        }

        StringBuilder out = new StringBuilder("{\"items\":[");
        boolean first = true;
        for (String[] it : items) {
            List<String> jndi = new ArrayList<>();
            String rendered = render(it[1], jndi);
            if (!first) out.append(',');
            first = false;
            out.append("{\"source\":").append(js(it[0]))
               .append(",\"raw\":").append(js(it[1]))
               .append(",\"rendered\":").append(js(rendered))
               .append(",\"changed\":").append(!rendered.equals(it[1]))
               .append(",\"jndi\":[");
            for (int k = 0; k < jndi.size(); k++) {
                if (k > 0) out.append(',');
                out.append(js(jndi.get(k)));
            }
            out.append("]}");
        }
        out.append("]}");
        byte[] resp = out.toString().getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(200, resp.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(resp);
        }
    }

    // render logs msg through real Log4j and returns exactly what the layout wrote.
    private static String render(String msg, List<String> jndi) {
        synchronized (LOCK) {
            CAPTURE.getBuffer().setLength(0);
            Hook.drain();
            try {
                log.info(msg);
            } catch (Throwable t) {
                jndi.addAll(Hook.drain());
                return "<<log4j threw " + t.getClass().getName() + ">>";
            }
            jndi.addAll(Hook.drain());
            return CAPTURE.toString();
        }
    }

    private static String dec(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    private static byte[] readBounded(InputStream in, int max) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) {
            if (bo.size() + n > max) {
                bo.write(buf, 0, max - bo.size());
                break;
            }
            bo.write(buf, 0, n);
        }
        return bo.toByteArray();
    }

    private static String js(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7e) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
