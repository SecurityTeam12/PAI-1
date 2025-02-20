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
public class Server implements CommandLineRunner{
	
	/**
	 * @param args
	 * @throws IOException 
	 * @throws InterruptedException 
	 */

	 @Autowired
	 UserRepository userRepository;


	public void run(String... args) throws IOException,          
                           InterruptedException {

		// perpetually listen for clients
		ServerSocket serverSocket = new ServerSocket(3343);
		while (true) {

		// wait for client connection and check login information
		try {
		System.err.println("Waiting for connection...");
						
		Socket socket = serverSocket.accept();

		// open BufferedReader for reading data from client
		BufferedReader input = new BufferedReader(new
                               InputStreamReader(socket.getInputStream()));

		// open PrintWriter for writing data to client
		PrintWriter output = new PrintWriter(new 
                    OutputStreamWriter(socket.getOutputStream()));
		String userName = input.readLine();
		String password = input.readLine();

		List<User> users = userRepository.findAll();
		
		System.out.println(users);
		
		output.println("User, " + userName);
		output.println("Pass, " + password);
			

		output.close();
		input.close();
		socket.close();

		} // end try

		// handle exception communicating with client
		catch (IOException ioException) {
			ioException.printStackTrace();
		}

	} 

   }

}