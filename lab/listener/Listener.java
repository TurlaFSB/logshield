// Logging-only listener for the LogShield lab.
//
// It records connection attempts and DNS queries made by the canary app and
// NEVER sends anything back that could be interpreted as a JNDI/LDAP/RMI
// response: TCP connections are read once and closed, and DNS answers point
// only at 127.0.0.1. It exists to answer one question: "did a real, vulnerable
// Log4j try to resolve a lookup for this input?"
//
// Control API (bound to LISTEN_ADDR, default 127.0.0.1):
//   GET  /health              -> ok
//   GET  /events?after=N      -> {"events":[...],"last":M}
//   POST /reset               -> clears events
//
// Environment: LISTEN_ADDR, TCP_PORTS (comma list), DNS_PORT, CONTROL_PORT.
// Ports below 1024 need root. Use only on an isolated lab network.
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class Listener {
    static final List<String> events = new ArrayList<>();

    static String env(String k, String d) {
        String v = System.getenv(k);
        return v == null || v.isEmpty() ? d : v;
    }

    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20 || c > 0x7e) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    static void record(String kind, int port, String peer, String data) {
        synchronized (events) {
            events.add("{\"n\":" + (events.size() + 1) + ",\"ts\":" + System.currentTimeMillis() + ",\"kind\":" + q(kind)
                + ",\"port\":" + port + ",\"peer\":" + q(peer) + ",\"data\":" + q(data) + "}");
        }
    }

    static void tcp(InetAddress addr, int port) throws Exception {
        ServerSocket ss = new ServerSocket(port, 50, addr);
        Thread t = new Thread(() -> {
            while (true) {
                try (Socket s = ss.accept()) {
                    s.setSoTimeout(300);
                    byte[] buf = new byte[256];
                    int n = 0;
                    try {
                        InputStream in = s.getInputStream();
                        n = Math.max(0, in.read(buf));
                    } catch (java.net.SocketTimeoutException ignored) {
                        // the client sent nothing; the connection itself is the signal
                    }
                    StringBuilder hex = new StringBuilder();
                    for (int i = 0; i < Math.min(n, 64); i++) hex.append(String.format("%02x", buf[i]));
                    record("tcp", port, s.getRemoteSocketAddress().toString(), hex.toString());
                    // Deliberately no reply: close and let the client fail.
                } catch (Exception e) {
                    if (ss.isClosed()) return;
                }
            }
        }, "tcp-" + port);
        t.setDaemon(true);
        t.start();
    }

    static void dns(InetAddress addr, int port) throws Exception {
        DatagramSocket ds = new DatagramSocket(port, addr);
        Thread t = new Thread(() -> {
            byte[] buf = new byte[512];
            while (true) {
                try {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    ds.receive(p);
                    byte[] in = java.util.Arrays.copyOf(p.getData(), p.getLength());
                    if (in.length < 17) continue;
                    StringBuilder name = new StringBuilder();
                    int i = 12;
                    while (i < in.length && in[i] != 0) {
                        int len = in[i] & 0xff;
                        if (len > 63 || i + 1 + len > in.length) break;
                        if (name.length() > 0) name.append('.');
                        name.append(new String(in, i + 1, len, StandardCharsets.ISO_8859_1));
                        i += 1 + len;
                    }
                    int end = i + 1; // after the zero label
                    if (end + 4 > in.length) continue;
                    int qtype = ((in[end] & 0xff) << 8) | (in[end + 1] & 0xff);
                    record("dns", port, p.getSocketAddress().toString(), name + " type=" + qtype);

                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    out.write(in, 0, 2); // id
                    out.write(0x81); out.write(0x80); // response, recursion available
                    out.write(0); out.write(1); // QDCOUNT
                    boolean answerA = qtype == 1 || qtype == 255;
                    out.write(0); out.write(answerA ? 1 : 0); // ANCOUNT
                    out.write(0); out.write(0); out.write(0); out.write(0);
                    out.write(in, 12, end + 4 - 12); // question
                    if (answerA) {
                        out.write(0xc0); out.write(0x0c); // name pointer
                        out.write(0); out.write(1); out.write(0); out.write(1); // A, IN
                        out.write(0); out.write(0); out.write(0); out.write(0); // TTL 0
                        out.write(0); out.write(4);
                        out.write(127); out.write(0); out.write(0); out.write(1);
                    }
                    byte[] resp = out.toByteArray();
                    ds.send(new DatagramPacket(resp, resp.length, p.getSocketAddress()));
                } catch (Exception e) {
                    if (ds.isClosed()) return;
                }
            }
        }, "dns-" + port);
        t.setDaemon(true);
        t.start();
    }

    public static void main(String[] args) throws Exception {
        InetAddress addr = InetAddress.getByName(env("LISTEN_ADDR", "127.0.0.1"));
        for (String p : env("TCP_PORTS", "389,636,1099,900,1389").split(",")) tcp(addr, Integer.parseInt(p.trim()));
        dns(addr, Integer.parseInt(env("DNS_PORT", "53")));

        HttpServer http = HttpServer.create(new InetSocketAddress(addr, Integer.parseInt(env("CONTROL_PORT", "9001"))), 0);
        http.createContext("/health", ex -> reply(ex, 200, "ok\n"));
        http.createContext("/reset", ex -> {
            if (!"POST".equals(ex.getRequestMethod())) { reply(ex, 405, "POST only\n"); return; }
            synchronized (events) { events.clear(); }
            reply(ex, 200, "reset\n");
        });
        http.createContext("/events", ex -> {
            int after = 0;
            String qs = ex.getRequestURI().getRawQuery();
            if (qs != null && qs.startsWith("after=")) {
                try { after = Integer.parseInt(qs.substring(6)); } catch (NumberFormatException ignored) { }
            }
            StringBuilder b = new StringBuilder("{\"events\":[");
            int last;
            synchronized (events) {
                last = events.size();
                for (int i = Math.max(0, after); i < last; i++) {
                    if (i > after) b.append(',');
                    b.append(events.get(i));
                }
            }
            reply(ex, 200, b.append("],\"last\":").append(last).append("}\n").toString());
        });
        http.start();
        System.out.println("listener ready");
    }

    static void reply(com.sun.net.httpserver.HttpExchange ex, int status, String body) throws java.io.IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }
}
