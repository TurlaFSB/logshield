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
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
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
        // With no log4j2 configuration file the root logger defaults to ERROR,
        // which would silently drop every info() call below.
        cfg.getRootLogger().setLevel(Level.INFO);
        cfg.getRootLogger().addAppender(appender, Level.INFO, null);
        ctx.updateLoggers();
        log = LogManager.getLogger("canary");

        // Refuse to run if the capture does not work: a broken oracle must
        // never look like "Log4j ignored everything".
        String probe = render("canary-selftest", new ArrayList<>());
        if (!probe.equals("canary-selftest")) {
            System.err.println("canary: self-test failed, Log4j captured [" + probe + "]");
            System.exit(1);
        }

        ServerSocket srv = new ServerSocket(Integer.parseInt(portS), 128, InetAddress.getByName(addr));
        java.util.concurrent.ExecutorService pool = Executors.newFixedThreadPool(8);
        Thread acceptor = new Thread(() -> {
            for (;;) {
                try {
                    final Socket c = srv.accept();
                    pool.execute(() -> serve(c));
                } catch (IOException e) {
                    return;
                }
            }
        }, "accept");
        acceptor.start();
        System.out.println("canary listening on " + addr + ":" + portS + " (log4j-core 2.14.1, lookups ON)");
    }

    private static void serve(Socket c) {
        try (Socket sock = c) {
            sock.setSoTimeout(5000);
            RawHttp.Req req;
            try {
                req = RawHttp.parse(sock.getInputStream(), 65536, maxBody);
            } catch (IOException e) {
                respond(sock, 400, "bad request: " + e.getMessage());
                return;
            }
            if (req == null) return;
            respond(sock, 200, report(req));
        } catch (Exception ignored) {
            // the peer went away; nothing to report
        }
    }

    private static void respond(Socket sock, int status, String body) {
        try {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            String head = "HTTP/1.1 " + status + (status == 200 ? " OK" : " Bad Request") + "\r\n"
                + "Content-Type: " + (status == 200 ? "application/json" : "text/plain") + "\r\n"
                + "Content-Length: " + b.length + "\r\nConnection: close\r\n\r\n";
            OutputStream os = sock.getOutputStream();
            os.write(head.getBytes(StandardCharsets.ISO_8859_1));
            os.write(b);
            os.flush();
        } catch (IOException ignored) {
            // ignore
        }
    }

    private static String report(RawHttp.Req req) {
        List<String[]> items = new ArrayList<>(); // {source, raw}
        items.add(new String[] {"method", req.method});
        String target = req.target;
        int q = target.indexOf('?');
        String path = q < 0 ? target : target.substring(0, q);
        items.add(new String[] {"path", path});
        items.add(new String[] {"path.decoded", dec(path)});
        if (q >= 0) {
            String query = target.substring(q + 1);
            items.add(new String[] {"query", query});
            items.add(new String[] {"query.decoded", dec(query)});
        }
        for (String[] h : req.headers) {
            items.add(new String[] {"header-name", h[0]});
            items.add(new String[] {"header:" + h[0], h[1]});
        }
        if (req.body.length > 0) {
            items.add(new String[] {"body", new String(req.body, StandardCharsets.UTF_8)});
        }
        // What a typical framework would decode and hand to a logger.
        for (String[] v : AppViews.of(req)) {
            items.add(new String[] {"view:" + v[0], v[1]});
        }
        StringBuilder out = new StringBuilder("{\"items\":[");
        boolean first = true;
        for (String[] it : items) {
            List<String> jndi = new ArrayList<>();
            String rendered = render(it[1], jndi);
            // Text without "${" must come back unchanged; empty output means nothing was
            // captured. (Text with "${" may legitimately render empty, e.g. "${::-}".)
            String err = (rendered.isEmpty() && !it[1].isEmpty() && !it[1].contains("${")) ? "empty-capture" : null;
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
            out.append("]");
            if (err != null) out.append(",\"error\":").append(js(err));
            out.append("}");
        }
        out.append("]}");
        return out.toString();
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
