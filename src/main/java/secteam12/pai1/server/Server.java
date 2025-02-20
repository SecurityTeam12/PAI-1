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
import secteam12.pai1.repository.UserRepository;

@Component
public class Server implements CommandLineRunner {

    @Autowired
    UserRepository userRepository;


    @Override
    public void run(String... args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(3343);
        System.err.println("Server started and waiting for connections...");

        while (true) {
            try {
                Socket socket = serverSocket.accept();
                System.err.println("Client connected.");

                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

                // Send menu options to client
                output.println("1. Login");
                output.println("2. Register");
                output.println("Enter your choice:");

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
                    }
                } else if ("2".equals(option)) {
                    // Handle registration
                    String newUserName = input.readLine();
                    String newPassword = input.readLine();

                    if (registerUser(newUserName, newPassword)) {
                        output.println("Registration successful. You can now log in.");
                    } else {
                        output.println("Registration failed. Username already exists.");
                    }
                } else {
                    output.println("Invalid option selected.");
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

	private User loginUser(String userName, String password) {
        List<User> users = userRepository.findAll();
        for (User user : users) {
            if (user.getUsername().equals(userName) && user.getPassword().equals(password)) {
                return user;
            }
        }
        return null;
    }

    private boolean registerUser(String userName, String password) {
        if (userRepository.findByUsername(userName) != null) {
            return false; // Username already exists
        }
        User newUser = new User();
        newUser.setUsername(userName);
        newUser.setPassword(password);
        userRepository.save(newUser);
        return true;
    }
}