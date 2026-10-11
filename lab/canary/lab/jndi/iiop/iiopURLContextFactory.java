package lab.jndi.iiop;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;

/** Recording stand-in for the JDK iiop URL context factory (see lab.jndi.Hook). */
public final class iiopURLContextFactory implements ObjectFactory {
    @Override
    public Object getObjectInstance(Object urlInfo, Name name, Context nameCtx, Hashtable<?, ?> env) {
        return lab.jndi.Hook.instance("iiop", env);
    }
}
