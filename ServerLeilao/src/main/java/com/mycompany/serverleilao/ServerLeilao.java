package com.mycompany.serverleilao;

import com.mycompany.view.MainFrame;
import javax.swing.SwingUtilities;

/**
 *
 * @author nandones
 */
public class ServerLeilao {

    public static void main(String[] args) {
        swingTest();
    }
    
    public static void swingTest(){
        SwingUtilities.invokeLater(() -> {
            MainFrame mainFrame = new MainFrame();
            mainFrame.setVisible(true); // Torna o JFrame visível
        });
    }
}
