package secteam12.pai1.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import secteam12.pai1.model.User;
import secteam12.pai1.repository.TransactionRepository;
import secteam12.pai1.repository.UserRepository;
import secteam12.pai1.utils.PwnedPasswordChecker;
import secteam12.pai1.model.Transaction;

@Component
public class Server implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TransactionRepository transactionRepository;

    @Override
    public void run(String... args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(3343);
        while (true) {
            try {
                System.err.println("Waiting for connection...");

                Socket socket = serverSocket.accept();

                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

                // Send menu options to client
                output.println("Welcome! Please select an option:");
                output.println("1. Login");
                output.println("2. Register");

                String option = input.readLine();

                if ("1".equals(option)) {
                    // Handle login
                    String userName = input.readLine();
                    String password = input.readLine();

                    User user = loginUser(userName, password);
                    if (user == null) {
                        output.println("Invalid login information");
                    } else {
                        output.println("Welcome, " + user.getUsername() + "!");
                        handleAuthenticatedUser(input, output, user);
                        
                    }
                } else if ("2".equals(option)) {
                    // Handle registration
                    String newUserName = input.readLine();
                    String newPassword = input.readLine();
                        if (registerUser(newUserName, newPassword)) {
                            output.println("Registration successful. You can now log in.");
                            break;
                        } else {
                            output.println("Registration failed. Please try again.");
                        }
                } else {
                    output.println("Invalid option selected.");
                }

                output.close();
                input.close();
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void handleAuthenticatedUser(BufferedReader input, PrintWriter output, User user) throws IOException {
        while (true) {
            output.println("Select an option:");

            String option = input.readLine();
    
            if ("0".equals(option)) {
                // Handle transaction
                String transaction = input.readLine();
                String[] parts = transaction.split(",");
                if (parts.length != 3) {
                    output.println("Invalid transaction format.");
                    continue;
                }
                Transaction newTransaction = new Transaction();
                newTransaction.setSourceAccount(parts[0]);
                newTransaction.setDestinationAccount(parts[1]);
                newTransaction.setAmount(Double.parseDouble(parts[2]));

                

                transactionRepository.save(newTransaction);


                output.println("Transaction received: " + transaction);
            } else if ("1".equals(option)) {
                // Handle logout
                output.println("Logged out successfully.");
                break;
            } else {
                output.println("Invalid option selected.");
            }
        }
    }

    private User loginUser(String userName, String password) {
        List<User> users = userRepository.findAll();
        for (User user : users) {
            if (user.getUsername().equals(userName) && user.getPassword().equals(password)) {
                return user;
            }
        }
        return null;
    }


    private boolean registerUser(String userName, String password) throws Exception {
        if (userRepository.findByUsername(userName) != null) {
            return false; // Username already exists
        }
        if (!checkPasswordSecurity(password)) {
            return false;
        }
        User newUser = new User();
        newUser.setUsername(userName);
        newUser.setPassword(password);
        userRepository.save(newUser);
        return true;
    }

    private Boolean checkPasswordSecurity(String password) throws Exception {
        Boolean hasUppercase = !password.equals(password.toLowerCase());
        Boolean hasLowercase = !password.equals(password.toUpperCase());
        Boolean hasNumber = password.matches(".*\\d.*");
        Boolean hasSpecialChar = !password.matches("[A-Za-z0-9 ]*");
        Boolean hasCorrectLength = password.length() >= 8;
        Boolean hasBeenPwned = PwnedPasswordChecker.isPasswordPwned(password);

        if (hasUppercase && hasLowercase && hasNumber && hasSpecialChar && hasCorrectLength && !hasBeenPwned) {
            return true;
        }
        return false;


    }
}