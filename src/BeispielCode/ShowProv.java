package BeispielCode;

import java.security.Provider;
import java.security.Security;

/**
 * Dieses Beispiel gibt alle installierten Kryptographie-Provider aus.
 */
public class ShowProv {
    public static void main(String[] args) {
        int i;
        Provider[] provider = Security.getProviders();
        for (i = 0; i < provider.length; i++)
            System.out.println("Provider " + i + ": " + provider[i].getInfo());
    }
}
