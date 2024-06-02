package com.rutar.dmf_analyzer;

import java.awt.*;
import javax.swing.*;

/**
 * Клас DMF_Analyzer_Demo
 * @author Rutar_Andriy
 * 01.06.2024
 */

public class DMF_Analyzer_Demo extends JFrame {

///////////////////////////////////////////////////////////////////////////////

public DMF_Analyzer_Demo() { initComponents(); }

///////////////////////////////////////////////////////////////////////////////

@SuppressWarnings("unchecked")
    private void initComponents() {//GEN-BEGIN:initComponents

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        GroupLayout layout = new GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGap(0, 400, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGap(0, 300, Short.MAX_VALUE)
        );

        pack();
    }//GEN-END:initComponents

///////////////////////////////////////////////////////////////////////////////

public static void main (String args[]) {

    EventQueue.invokeLater(() -> {
        new DMF_Analyzer_Demo().setVisible(true);
    });
}

///////////////////////////////////////////////////////////////////////////////

    // Variables declaration - do not modify//GEN-BEGIN:variables
    // End of variables declaration//GEN-END:variables

// Кінець класу DMF_Analyzer_Demo /////////////////////////////////////////////

}