package lab.jndi;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NamingException;

/**
 * Hermetic JNDI oracle. When the JVM runs with
 * -Djava.naming.factory.url.pkgs=lab.jndi, JNDI resolves URL schemes through
 * the factories in this package instead of the JDK's. They record the exact
 * name that real Log4j asked to look up and then fail the lookup, so no
 * network traffic is ever produced. The canary reports what was recorded.
 */
public final class Hook {
    private static final List<String> SEEN = new ArrayList<>();

    private Hook() {}

    static synchronized void record(String name) {
        SEEN.add(name);
    }

    /** Returns and clears everything recorded since the last call. */
    public static synchronized List<String> drain() {
        List<String> out = new ArrayList<>(SEEN);
        SEEN.clear();
        return out;
    }

    /** A Context whose lookup records the name and then fails. */
    static Context context(final String scheme) {
        InvocationHandler h = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method m, Object[] args) throws Throwable {
                String n = m.getName();
                if (n.equals("lookup") || n.equals("lookupLink")) {
                    Object a = args[0];
                    record(a instanceof Name ? a.toString() : String.valueOf(a));
                    throw new NamingException("lab hook: " + scheme + " lookup recorded and refused");
                }
                if (n.equals("close")) {
                    return null;
                }
                if (n.equals("toString")) {
                    return "lab.jndi.Hook(" + scheme + ")";
                }
                if (n.equals("hashCode")) {
                    return System.identityHashCode(proxy);
                }
                if (n.equals("equals")) {
                    return proxy == args[0];
                }
                throw new NamingException("lab hook: " + n + " unsupported");
            }
        };
        return (Context) Proxy.newProxyInstance(Hook.class.getClassLoader(), new Class<?>[] {Context.class}, h);
    }

    /** Shared by the per-scheme factories. */
    public static Object instance(String scheme, Hashtable<?, ?> env) {
        return context(scheme);
    }
}
