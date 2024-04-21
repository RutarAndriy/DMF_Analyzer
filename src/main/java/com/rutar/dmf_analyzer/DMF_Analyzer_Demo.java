package com.rutar.dmf_analyzer;

import java.awt.*;
import javax.swing.*;
import java.awt.event.*;

// ............................................................................

/**
 * Клас DMF_Analyzer_Demo
 * @author Rutar_Andriy
 * 21.04.2024
 */

public class DMF_Analyzer_Demo extends JFrame {

///////////////////////////////////////////////////////////////////////////////

public DMF_Analyzer_Demo() { initComponents(); }

///////////////////////////////////////////////////////////////////////////////

private void initComponents() {

label_hint    = new JLabel();
field_input   = new JTextField();
btn_random    = new JButton();
sep           = new JSeparator();
panel_buttons = new JPanel();
btn_sum       = new JButton();
btn_product   = new JButton();
btn_aMean     = new JButton();
btn_qMean     = new JButton();

setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
setTitle("DMF_Analyzer Demo");
setPreferredSize(new Dimension(500, 91));
setResizable(false);

label_hint.setHorizontalAlignment(SwingConstants.CENTER);
label_hint.setText("Введіть числа, розділяючи їх комою");

field_input.setHorizontalAlignment(JTextField.CENTER);

btn_random.setText("<html><body align=\"center\">Згенерувати<br/>випадкові числа</body></html>");
btn_random.setToolTipText("<html><body align=\"center\">Згенерувати випадкову кількість<br/>випадкових чисел</body></html>");
btn_random.setActionCommand("btn_random");
btn_random.setMargin(new Insets(2, 9, 2, 9));
btn_random.addActionListener(this::onButtonClick);

panel_buttons.setLayout(new GridLayout(1, 0));

btn_sum.setText("Сума");
btn_sum.setToolTipText("Розрахувати суму введених чисел");
btn_sum.setActionCommand("btn_sum");
btn_sum.addActionListener(this::onButtonClick);
panel_buttons.add(btn_sum);

btn_product.setText("Добуток");
btn_product.setToolTipText("Розрахувати добуток введених чисел");
btn_product.setActionCommand("btn_product");
btn_product.addActionListener(this::onButtonClick);
panel_buttons.add(btn_product);

btn_aMean.setText("x̅");
btn_aMean.setToolTipText("Розрахувати середнє арифметичне значення");
btn_aMean.setActionCommand("btn_aMean");
btn_aMean.addActionListener(this::onButtonClick);
panel_buttons.add(btn_aMean);

btn_qMean.setText("x(rms)");
btn_qMean.setToolTipText("Розрахувати середнє квадратичне значення");
btn_qMean.setActionCommand("btn_qMean");
btn_qMean.addActionListener(this::onButtonClick);
panel_buttons.add(btn_qMean);

GroupLayout layout = new GroupLayout(getContentPane());
getContentPane().setLayout(layout);
layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
    .addGroup(layout.createSequentialGroup()
        .addGap(5, 5, 5)
        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addComponent(sep)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(label_hint, GroupLayout.DEFAULT_SIZE, 382, Short.MAX_VALUE)
                    .addComponent(field_input))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btn_random, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
            .addComponent(panel_buttons, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        .addGap(5, 5, 5))
);
layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
    .addGroup(layout.createSequentialGroup()
        .addGap(5, 5, 5)
        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
            .addComponent(btn_random)
            .addGroup(layout.createSequentialGroup()
                .addComponent(label_hint)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(field_input, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
        .addComponent(sep, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
        .addComponent(panel_buttons, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
        .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
);

pack();
setLocationRelativeTo(null);

}

///////////////////////////////////////////////////////////////////////////////

private void onButtonClick (ActionEvent evt) {
    
    String command = ((JButton)evt.getSource()).getActionCommand();
    
    if (command.equals("btn_random")) { generateRandomNumbers();
                                        return; }
    
    int checkInput = checkInput();
    if (checkInput > 0) { showErrorMessage(checkInput);
                          return; }
    
    switch (command) {
        case "btn_sum"     -> showResultMessage(0);
        case "btn_product" -> showResultMessage(1);
        case "btn_aMean"   -> showResultMessage(2);
        case "btn_qMean"   -> showResultMessage(3);
    }
}

///////////////////////////////////////////////////////////////////////////////

public static void main(String args[]) {

    // Правила оформлення проектів описані тут:
    // https://github.com/RutarAndriy/My_Coding_Rules

    EventQueue.invokeLater(() -> {
        new DMF_Analyzer_Demo().setVisible(true);
    });
}

///////////////////////////////////////////////////////////////////////////////

private JLabel     label_hint;
private JTextField field_input;
private JButton    btn_random;
private JSeparator sep;
private JPanel     panel_buttons;
private JButton    btn_sum;
private JButton    btn_product;
private JButton    btn_aMean;
private JButton    btn_qMean;

///////////////////////////////////////////////////////////////////////////////

private int checkInput() {

    String input = field_input.getText().replaceAll(" ", "");

    if (input.isBlank())     { return 1; }
    if (input.endsWith(",")) { return 2; }

    String[] split = input.split(",");

    for (String value : split) {
        try { double D = Double.parseDouble(value);
              int    I = Integer.parseInt(value);
              if (D - I > 0)            { return 2; } }
        catch (NumberFormatException e) { return 2; }
    }

    return 0;

}

///////////////////////////////////////////////////////////////////////////////

private int[] getNumbers() {
    
    String input = field_input.getText().replaceAll(" ", "");
    String[] split = input.split(",");
    int[] numbers = new int[split.length];

    for (int z = 0; z < split.length; z++) {
        numbers[z] = Integer.parseInt(split[z]);
    }

    return numbers;

}

///////////////////////////////////////////////////////////////////////////////

private void generateRandomNumbers() {
            
    int random;
    String input;

    field_input.setText(null);
    int count = (int)(Math.random() * 7) + 5;

    for (int z = 0; z < count; z++) {
        random = (int)(Math.random() * 40) - 10;
        input = field_input.getText();
        field_input.setText(input + (input.isEmpty() ? "" : ", ") + random);
    }
}

///////////////////////////////////////////////////////////////////////////////

private void showResultMessage (int resultCode) {

    String text;
    String message;
    Number result;

    Color background = field_input.getBackground();
    field_input.setBackground(new Color(0xff66));

    String numbers = field_input.getText().replaceAll(" ", "")
                                          .replaceAll(",", ", ");

    field_input.setText(numbers);

    switch (resultCode) {
        case 0 ->
            { text = "Сума чисел\n(%s)\nдорівнює %d";
              result = DMF_Analyzer.sum(getNumbers()); }
        case 1 ->
            { text = "Добуток чисел\n(%s)\nдорівнює %d";
              result = DMF_Analyzer.product(getNumbers()); }
        case 2 ->
            { text = "Середнє арифметичне значення чисел\n(%s)\nдорівнює %.3f";
              result = DMF_Analyzer.arithmeticMean(getNumbers()); }
        default ->
            { text = "Середнє квадратичне значення чисел\n(%s)\nдорівнює %.3f";
              result = DMF_Analyzer.quadraticMean(getNumbers()); }
    }

    message = String.format(text, numbers, result);
    JOptionPane.showMessageDialog(btn_product, message,
                                 "Рузультат", JOptionPane.PLAIN_MESSAGE);

    field_input.setBackground(background);

}

///////////////////////////////////////////////////////////////////////////////

private void showErrorMessage (int errorCode) {

    Color background = field_input.getBackground();
    field_input.setBackground(new Color(0xff6666));

    String message = null;

    switch (errorCode) {
        case 1 -> message = "Поле введення не\nмістить жодних даних";
        case 2 -> message = "Помилка вводу.\nДопускаються тільки цілі числа";
    }

    JOptionPane.showMessageDialog(btn_product, message,
                                 "Помилка", JOptionPane.ERROR_MESSAGE);

    field_input.setBackground(background);

}

// Кінець класу DMF_Analyzer_Demo /////////////////////////////////////////////

}
