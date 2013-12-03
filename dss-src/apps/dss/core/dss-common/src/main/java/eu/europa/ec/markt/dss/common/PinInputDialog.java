/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.common;

import eu.europa.ec.markt.dss.signature.token.PasswordInputCallback;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

/**
 * Holds the implementation of some eID related dialogs.
 * 
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (lun., 06 juin 2011) $
 */

@SuppressWarnings("serial")
public class PinInputDialog extends JDialog implements PasswordInputCallback {

    static enum Result {
        OK, CANCEL
    };

    public static final int MIN_PIN_SIZE = 4;

    public static final int MAX_PIN_SIZE = 12;

    private final Component view;

    private Result result = null;

    private JPanel mainPanel;
    private JButton okButton;
    private JPanel buttonPanel;
    private JButton cancelButton;
    private JPasswordField passwordField;

    /**
     * Create a Dialog with the provided parent The default constructor for Dialogs.
     * 
     * @param view
     */
    public PinInputDialog(Component view) {
        super((Frame) null, true);
        this.view = view;
        initComponents();

        /* If the user press the OK button */
        okButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                result = Result.OK;
                dispose();
            }
        });
        okButton.setName("ok");

        /* If the user press the CANCEL button */
        cancelButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                result = Result.CANCEL;
                dispose();
            }
        });

        /* If the user press enter */
        passwordField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                int pinSize = passwordField.getPassword().length;
                if (MIN_PIN_SIZE <= pinSize && pinSize <= MAX_PIN_SIZE) {
                    result = Result.OK;
                    dispose();
                }
            }
        });
        passwordField.setName("password");

        passwordField.addKeyListener(new KeyListener() {

            public void keyPressed(KeyEvent e) {
            }

            public void keyReleased(KeyEvent e) {
                int pinSize = passwordField.getPassword().length;
                if (MIN_PIN_SIZE <= pinSize && pinSize <= MAX_PIN_SIZE) {
                    okButton.setEnabled(true);
                } else {
                    okButton.setEnabled(false);
                }
            }

            public void keyTyped(KeyEvent e) {
            }
        });
    }

    private void initComponents() {

        // main panel
        mainPanel = new JPanel() {
            private static final long serialVersionUID = 1L;

            private static final int BORDER_SIZE = 20;

            @Override
            public Insets getInsets() {
                return new Insets(BORDER_SIZE, BORDER_SIZE, BORDER_SIZE, BORDER_SIZE);
            }
        };
        BoxLayout boxLayout = new BoxLayout(mainPanel, BoxLayout.PAGE_AXIS);
        mainPanel.setLayout(boxLayout);

        /* Fields */
        Box passwordPanel = Box.createHorizontalBox();
        JLabel promptLabel = new JLabel("Pin code : ");
        passwordPanel.add(promptLabel);
        passwordPanel.add(Box.createHorizontalStrut(5));
        passwordField = new JPasswordField(MAX_PIN_SIZE);
        promptLabel.setLabelFor(passwordField);
        passwordPanel.add(passwordField);
        mainPanel.add(passwordPanel);

        // button panel
        buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT)) {
            private static final long serialVersionUID = 1L;

            @Override
            public Insets getInsets() {
                return new Insets(0, 0, 5, 5);
            }
        };

        okButton = new JButton("Ok");
        okButton.setEnabled(false);
        buttonPanel.add(okButton);
        cancelButton = new JButton("Cancel");
        buttonPanel.add(cancelButton);

        setLayout(new BorderLayout());
        getContentPane().add(mainPanel, BorderLayout.CENTER);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);

        pack();
    }

    /**
     * Display a dialog that retrieves a pin code
     * 
     * @return
     */
    @Override
    public char[] getPassword() {

        setLocationRelativeTo(view);
        setVisible(true);

        if (result == Result.OK) {
            char[] pin = passwordField.getPassword();
            return pin;
        }

        throw new RuntimeException("operation canceled.");
    }

}