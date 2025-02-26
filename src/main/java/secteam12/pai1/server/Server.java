package secteam12.pai1.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import secteam12.pai1.model.Transaction;
import secteam12.pai1.model.User;
import secteam12.pai1.repository.TransactionRepository;
import secteam12.pai1.repository.UserRepository;

import secteam12.pai1.utils.MACUtil;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

@Component
public class Server implements CommandLineRunner {

    @Autowired
    UserRepository userRepository;

    @Autowired
    TransactionRepository transactionRepository;

    @Override
    public void run(String... args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(3343);
        System.err.println("Server started and waiting for connections...");

        while (true) {
            try {
                Socket socket = serverSocket.accept();
                System.err.println("Client connected.");

                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

                String option = input.readLine();

                if ("0".equals(option)) {
                    // Handle login

                    for(int i = 0; i < 3;i ++){

                        String nonce =  MACUtil.generateNonce();
                        output.println(nonce);
                        
                        String encodedKey = input.readLine();
                        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
                        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA512");
                        String receivedMAC = input.readLine();
    
                        String userName = input.readLine();
                        if (userName == null) {
                            break;
                        }
                        String password = input.readLine();
                        if (password == null) {
                            break;
                        }
    
    
                        if(MACUtil.verifyMAC(userName+password, nonce, key, receivedMAC)){
                            User user = loginUser(userName, password);
                            if (user == null) {
                                output.println("Invalid login information");
                            } else {
                                output.println("Welcome, " + user.getUsername() + "!");
                                handleAuthenticatedUser(input, output, user);
                                break;
                            }
                        }else {
                            output.println("Invalid MAC. Transaction rejected.");
                        }
                    }

                } else if ("1".equals(option)) {
                    // Handle registration
                    String nonce =  MACUtil.generateNonce();
                    output.println(nonce);
                    
                    String encodedKey = input.readLine();
                    byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
                    SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA512");
                    String receivedMAC = input.readLine();

                    String newUserName = input.readLine();
                    String newPassword = input.readLine();
                    if(newPassword.equals("null") || newUserName.equals("null")){
                        input.close();
                        output.close();
                        socket.close();
                        System.err.println("Client disconnected.");
                        continue;
                    }

                    if(MACUtil.verifyMAC(newUserName+newPassword, nonce, key, receivedMAC)){
                        if (registerUser(newUserName, newPassword)) {
                            output.println("Registration successful. You can now log in.");
                        } else {
                            output.println("Registration failed. Username already exists.");
                        }
                    }
                    
                }

                input.close();
                output.close();
                socket.close();
                System.err.println("Client disconnected.");

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        
    }

    public void handleAuthenticatedUser(BufferedReader input, PrintWriter output, User user) throws Exception {
        while (true) {
            String transactionsNumber = userRepository.findUserTransactionLenghtByUserId(user.getId()).toString();
            output.println(transactionsNumber);
            String option = input.readLine();
    
            if ("0".equals(option)) {
                String transaction = input.readLine();

                if (transaction.equals("null")) {
                    continue;
                }

                String nonce =  MACUtil.generateNonce();
                output.println(nonce);

                String encodedKey = input.readLine();
                byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
                SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA512");
                String receivedMAC = input.readLine();
                

                if (MACUtil.verifyMAC(transaction, nonce, key, receivedMAC)) {
                    String[] parts = transaction.split(",");

                    if (parts.length != 3) {
                        output.println("Invalid transaction format.");
                        continue;
                    }
                    

                    Transaction newTransaction = new Transaction();
                    newTransaction.setSourceAccount(parts[0]);
                    newTransaction.setDestinationAccount(parts[1]);
                    newTransaction.setAmount(Double.parseDouble(parts[2]));
                    newTransaction.setUser(user);

                    
                    transactionRepository.save(newTransaction);
                    output.println("Transaction received: " + transaction);
    
                } else {
                    output.println("Invalid MAC. Transaction rejected.");
                }
                
            } else if ("1".equals(option)) {
                break;
            } else {
                output.println("Invalid option selected.");
            }
        }
    }

    public User loginUser(String userName, String password){
        List<User> users = userRepository.findAll();

        // Argon2 setup for password hashing
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

        for (User user : users) {
            if (user.getUsername().equals(userName) && argon2.verify(user.getHash(), (password + user.getSalt()).toCharArray())) {
                return user;
            }
        }
        return null;
    }

    public boolean registerUser(String userName, String password) {
        if (userRepository.findByUsername(userName) != null) {
            return false; // Username already exists
        }

        // Argon2 setup for password hashing
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
        int iterations = 10;
        int memory = 65536;
        int parallelism = 1;

        // Generating a random salt
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        String saltBase64 = Base64.getEncoder().encodeToString(salt);



        // Hash password
        String hash = argon2.hash(iterations, memory, parallelism, (password + saltBase64).toCharArray());

        User newUser = new User();
        newUser.setUsername(userName);
        newUser.setHash(hash);
        newUser.setSalt(saltBase64);
        userRepository.save(newUser);

        return true;
    }
}