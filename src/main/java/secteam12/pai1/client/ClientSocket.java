package secteam12.pai1.client;

import java.io.*;
import java.net.Socket;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.JOptionPane;

import secteam12.pai1.utils.MACUtil;

public class ClientSocket {
    private static final String HMAC_SHA512 = "HmacSHA512";

    public static void main(String[] args) throws Exception{
        try {
            // connect to server
            while(true){
                Socket socket = new Socket("localhost", 3343);
                // create PrintWriter for sending data to server
                PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

                // create BufferedReader for reading server response
                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                // read and display menu options from server
                String menuOption1 = input.readLine();
                String menuOption2 = input.readLine();
                String menuOption3 = input.readLine();

                String menu = menuOption1 + "\n" + menuOption2 + "\n" + menuOption3;
                String option = JOptionPane.showInputDialog(menu);

                // send selected option to server
                output.println(option);

                if ("1".equals(option)) {
                    for (int i = 0; i < 3; i++) {
                        String userName = JOptionPane.showInputDialog("Enter username:");
                        output.println(userName);
                        String password = JOptionPane.showInputDialog("Enter password:");
                        output.println(password);

                        // read response from server
                        String response = input.readLine();
                        if (response.startsWith("Welcome")) {
                            handleAuthenticatedUser(input, output,response);
                            break;
                        }else{
                            Thread.sleep(3000);
                            JOptionPane.showMessageDialog(null, response);
                        }
                    }
                    JOptionPane.showMessageDialog(null, "Too many login attempts. Exiting...");

                } else if ("2".equals(option)) {
                    // Handle registration
                    String newUserName = JOptionPane.showInputDialog("Enter new username:");
                    output.println(newUserName);
                    String newPassword = JOptionPane.showInputDialog("Enter new password:");
                    output.println(newPassword);
                    
                    // read response from server
                    String response = input.readLine();
                    JOptionPane.showMessageDialog(null, response);

                } else {
                    String resposne = input.readLine();
                    JOptionPane.showMessageDialog(null, resposne);
                    break;
                }

                // clean up streams and Socket
                output.close();
                input.close();
                socket.close();
            }
            

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleAuthenticatedUser(BufferedReader input, PrintWriter output,String welcome) throws Exception {
        while (true) {
            // read and display authenticated user menu options from server

            String menu = welcome + "\n" + input.readLine();
            int option = JOptionPane.showOptionDialog(null, menu, "Select an option", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[] { "Perform a Transaction", "Logout" },null);

            // send selected option to server
            output.println(option);

            if (option == 0) {
                // Handle transaction
                String transaction = JOptionPane.showInputDialog("Enter transaction in format 'Cuenta origen, Cuenta destino, Cantidad transferida':");
                String nonce  =  input.readLine();

                KeyGenerator keyGenerator = KeyGenerator.getInstance(HMAC_SHA512);
                SecretKey key = keyGenerator.generateKey();
                String secureMac = MACUtil.generateMAC(transaction, nonce,key);
                output.println(transaction);

                // read response from server
                String response = input.readLine();
                JOptionPane.showMessageDialog(null, response);

            } else if (option == 1) {
                // Handle logout
                JOptionPane.showMessageDialog(null, "Logged out successfully.");
                break;

            } else {
                break;
            }
        }
    }
}