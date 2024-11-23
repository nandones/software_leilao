package com.mycompany.serverleilao;

import static com.mycompany.serverleilao.ServerCommunication.serverSocket;
import com.mycompany.view.MainFrame;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.SwingUtilities;

/**
 *
 * @author nandones
 */
public class ServerLeilao {
    
    public static final String SERVER_PUBLIC_KEY_BASE64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAotfntXqe1eKG9LsERj+PUuMM4BfyHfxJe42wB4/1DDLf+32/DybXjj2/I4uLXZY68o3KKYoc1/t6ACkvD58Jcr7v8t4sbmpDjiXGg8tcCw7GBoJd0fSXF1ZQjYdc7SnHnuT1kiF0VOcVsABRD7xqd7+RZeOufQP+b1edI5L9gQQpAOG/jVN0ZgGJ1WOthbxMYsfnstoEicwYYE/XFiz0LJV9CdaZnRhY8xKYM+JHpDcyLHR5+tpToEjlOlZlB1l3+/1oOMy48JIoPp+svzCi3ISs1SpazrAjy5rO3vpevg5TBLAiQbasb+Z6yCs6v9dhJF+KxxOaKddyx/7Gj+X8uwIDAQAB";
    public static final String SERVER_PRIVATE_KEY_BASE64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCi1+e1ep7V4ob0uwRGP49S4wzgF/Id/El7jbAHj/UMMt/7fb8PJteOPb8ji4tdljryjcopihzX+3oAKS8Pnwlyvu/y3ixuakOOJcaDy1wLDsYGgl3R9JcXVlCNh1ztKcee5PWSIXRU5xWwAFEPvGp3v5Fl4659A/5vV50jkv2BBCkA4b+NU3RmAYnVY62FvExix+ey2gSJzBhgT9cWLPQslX0J1pmdGFjzEpgz4kekNzIsdHn62lOgSOU6VmUHWXf7/Wg4zLjwkig+n6y/MKLchKzVKlrOsCPLms7e+l6+DlMEsCJBtqxv5nrIKzq/12EkX4rHE5op13LH/saP5fy7AgMBAAECggEAQXtjhAEKdQSR80Bu4Ba3+gMuTsCiTjeAjwvzQJ89UUn18onmtd+PJ3Yh8dev05LRIm8s35ZXsexAa2ckMvpnULqB/54irMXTY4pCMQYp/ZJTxBNRSde6mBpP6xGHJyE5UeZM75W/U1LXUD5YWmUQRRYGEDxFkqTz/+7x0/fMM8AE+QwvND1DoULcmjlqYBpJP5NEwBMrglRZz+5h7Vi72bHFsol+uWSU1/OCbX3EwGgBJ6xKLtgONGFtY0k7ujh5uw302HPkjC1P5EwkbYiUeuCguQ9hTJ6raFLMMBGyLtDy7C3GPr+mDPgWZ5G3EQPcapnPdAqIGJlOVW3DfcY9yQKBgQDhx7tJZSgYVX3EA4HJXk7R1Lz9ZfxRjEP2jcb+tP4KSiLyrYt1PjaxIlz8pBdcGGsDZfJJ/hTfyRc9Ygv1d7mZP8FP8p8KJoK2K/Kyo6DkuQIycZL1ONndo6ef10oJFuCRa7F59YWs6HbpKfhpMzQ1+UymQlO+msn+NY6hgMslWQKBgQC4o6sf0aQ6dBvBdRfkDUVbLgJTJ9J4CR3+pR1OkFG7WFiUpQzUHS6jJvZPOT0BN2xn+Z1nIMiv017FI/ZXQv9zxLacGZVqISc9VEx/2XKISMWXeJ3UMxRBJMa7Yp0c4kNqk+IbxMc1fBkf3BXzrDV2nO9oFmXMDcnK51QWH4xsMwKBgQDb450IfydMg76Hr26wglO7Ujh5heD2PuhV8ICUwgsEVG2y8cf3eI7ldvUe7GT/wZw/ZANTgswrovoqQxooh+DPWuNXjJDN3vHAoA6vYmMpPvHf1PLuNt8gV+nB53foYEp39m2TvMXiv0hIDyMqub6orlKzPbe306LUHK77paaziQKBgDeY4PBl2gPX7nukXJtI+7dm9UBA33lRlXyWD2sWveWhxpqL0H8WgnKSSty0KZByNexhF2p0TrnS9dh66bSA8hbUBwCeG4Wnkf8/oQFmYrxy3TytDylUcCblggnuucx2vUIcYZtm9209fvs+9EU5d6fNvbEj/WciR78XRRScT1ZNAoGBAIPYAiUHcFw7jaZymP0NGGNV/wD/Oh59HwFdkyN1UIidY2VQS1xL/XA5/QY2oonsYPbL4ia85e+3COGhFiD95v4m5/YyfZ38xpBe5lR4HxedToWtYA13Qc7ikqU1crYSHpC3TG+c5ZMozPVdmdNHx2+FaBzkQDBA94HQ1jJeh74C";
    
    public static final PublicKey SERVER_PUBLIC_KEY_BYTES = ServerCryptoUtils.convertBase64StringToPublicKey(SERVER_PUBLIC_KEY_BASE64);
    public static final PrivateKey SERVER_PRIVATE_KEY_BYTES = ServerCryptoUtils.convertBase64StringToPrivateKey(SERVER_PRIVATE_KEY_BASE64);

    public static void main(String[] args) {
        swingTest();
        //communicationTest();
        
    }
    
    public static void swingTest(){
        SwingUtilities.invokeLater(() -> {
            MainFrame mainFrame = new MainFrame();
            mainFrame.setVisible(true); // Torna o JFrame visível
        });
    }
    
    public static void communicationTest(){
        try {
            System.out.println("Server Adress: "+ InetAddress.getLocalHost().getHostAddress());
            ServerCommunication.serverSocket = new ServerSocket(12345);
            ServerCommunication.receiveAndProcessJoinRequest(serverSocket);
        } catch (IOException ex) {
            Logger.getLogger(ServerCommunication.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
