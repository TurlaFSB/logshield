import java.io.*;
import java.nio.charset.StandardCharsets;
public class RawHttpCheck {
  static RawHttp.Req p(String s) throws IOException { return RawHttp.parse(new ByteArrayInputStream(s.getBytes(StandardCharsets.ISO_8859_1)), 65536, 65536); }
  static void eq(Object a, Object b, String m){ if(!a.equals(b)){ System.out.println("FAIL "+m+": got ["+a+"] want ["+b+"]"); System.exit(1);} }
  public static void main(String[] x) throws Exception {
    RawHttp.Req r = p("GET /a/${jndi:ldap://e/x}?q=${jndi:ldap://e/y}&b=%24%7B HTTP/1.1\r\nHost: h\r\nX-${jndi:ldap://e/n}: v\r\nUA: ${jndi:ldap://e/u}\r\n\r\n");
    eq(r.method,"GET","method"); eq(r.target,"/a/${jndi:ldap://e/x}?q=${jndi:ldap://e/y}&b=%24%7B","target"); eq(r.version,"HTTP/1.1","ver");
    eq(r.headers.get(1)[0],"X-${jndi","hdr name"); eq(r.headers.get(1)[1],"ldap://e/n}: v","hdr name rest"); eq(r.headers.get(2)[1],"${jndi:ldap://e/u}","hdr value");
    r = p("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"); eq(new String(r.body),"hello","body");
    r = p("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nT: v\r\n\r\n"); eq(new String(r.body),"hello world","chunked");
    r = p("GET /with space/x HTTP/1.1\r\n\r\n"); eq(r.target,"/with space/x","spaces in target");
    r = p("GET /\n\n"); eq(r.target,"/","bare LF, no version");
    r = p("\r\n\r\nGET / HTTP/1.0\r\n\r\n"); eq(r.method,"GET","leading blank lines");
    r = p("POST / HTTP/1.1\r\nContent-Length: 999999\r\n\r\nabc"); eq(new String(r.body),"abc","short body");
    r = p("POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\nabc"); eq(r.body.length,0,"bad CL");
    if (RawHttp.parse(new ByteArrayInputStream(new byte[0]),100,100)!=null) { System.out.println("FAIL empty"); System.exit(1);}
    try { RawHttp.parse(new ByteArrayInputStream(("GET / HTTP/1.1\r\nX: "+"a".repeat(200)+"\r\n\r\n").getBytes()),64,10); System.out.println("FAIL limit"); System.exit(1);} catch(IOException e){}
    System.out.println("RawHttp OK");
  }
}
