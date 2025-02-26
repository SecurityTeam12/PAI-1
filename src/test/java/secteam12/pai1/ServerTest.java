package secteam12.pai1;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.junit.jupiter.api.Test;
import secteam12.pai1.server.Server;
import secteam12.pai1.utils.MACUtil;

import java.io.*;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import secteam12.pai1.model.Transaction;
import secteam12.pai1.model.User;
import secteam12.pai1.repository.UserRepository;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;


public class ServerTest extends Server{

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private Server server;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testServerClientInteraction() throws Exception {
        Thread serverThread = new Thread(() -> {
            try {
                server.run((String[]) null);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        serverThread.start();

        try (Socket clientSocket = new Socket("localhost", 3343);
             PrintWriter output = new PrintWriter(clientSocket.getOutputStream(), true);
             BufferedReader input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {

            output.println("1"); // Register option

            String response = input.readLine();
            assertNotNull(response); // Check the server is answering
        } finally {
            serverThread.interrupt();
        }
    }

    @Test
    public void testLoginProcess() throws Exception {
        Socket mockSocket = mock(Socket.class);
        BufferedReader mockInput = mock(BufferedReader.class);

        when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("Welcome User\n".getBytes()));
        when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        when(mockInput.readLine()).thenReturn("Welcome User");

        String username = "testUser";
        String password = "Strong1@Password";

        List<User> users = simulateRepositoryResponse();

        when(userRepository.findAll()).thenReturn(users);

        User loggedInUser = server.loginUser(username, password);
        assertNotNull(loggedInUser);
        assertEquals(username, loggedInUser.getUsername());
    }

    @Test
    public void testInvalidLoginProcess() throws Exception {
        Socket mockSocket = mock(Socket.class);
        BufferedReader mockInput = mock(BufferedReader.class);

        when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("Invalid User\n".getBytes()));
        when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        when(mockInput.readLine()).thenReturn("Invalid User");

        String username = "WrongUser";
        String password = "WrongPassword";

        List<User> users = simulateRepositoryResponse();
        when(userRepository.findAll()).thenReturn(users);

        User user = server.loginUser(username, password);
        assertNull(user);
        }

        @Test
        public void testRegisterUser() throws Exception {
    
        Socket mockSocket = mock(Socket.class);
        BufferedReader mockInput = mock(BufferedReader.class);

        when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("Registration successful. You can now log in.\n".getBytes()));
        when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        when(mockInput.readLine()).thenReturn("Registration successful. You can now log in.");

        String username = "newUser";
        String password = "NewUserPassword";

        when(userRepository.findByUsername(username)).thenReturn(null);

        boolean isRegistered = server.registerUser(username, password);
        assertTrue(isRegistered);
        }


        @Test
        public void testRegisterDuplicateUser() throws Exception {
    
            Socket mockSocket = mock(Socket.class);
            BufferedReader mockInput = mock(BufferedReader.class);

            when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("User already exists.\n".getBytes()));
            when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());

            when(mockInput.readLine()).thenReturn("User already exists.");

            String username = "existingUser";
            String password = "Password123";

            User existingUser = new User();
            existingUser.setUsername(username);

            when(userRepository.findByUsername(username)).thenReturn(existingUser);

            boolean isRegistered = server.registerUser(username, password);
            assertFalse(isRegistered);
        }

        @Test
        public void testSQLInjectionAttack() throws Exception {
            String maliciousUsername = "' OR '1'='1";
            String maliciousPassword = "' OR '1'='1";

            when(userRepository.findByUsername(maliciousUsername)).thenReturn(null);

            User user = server.loginUser(maliciousUsername, maliciousPassword);
            assertNull(user, "SQL Injection attack should not succeed");
        }

        @Test
        public void testBruteForceAttack() throws Exception {
            List<String> simulatedDicctionary = List.of("password", "123456", "qwerty", "letme in", "admin", "strongpassword", "password123", "12345678", "welcome", "monkey");
            String username = "testUser";
            String correctPassword = "Strong1@Password";

            List<User> users = simulateRepositoryResponse();
            when(userRepository.findAll()).thenReturn(users);

            for (String password : simulatedDicctionary) {

                User userTest = server.loginUser(username, password);
                assertNull(userTest, "Brute force attack attempt should not succeed");
            }

            User userCorrectTest = server.loginUser(username, correctPassword);
            assertNotNull(userCorrectTest, "Correct credentials should succeed after brute force attempts");
        }

        @Test
        public void testTransaction() throws Exception {
            Socket mockSocket = mock(Socket.class);
            BufferedReader mockInput = mock(BufferedReader.class);
        
            when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("Transaction received\n".getBytes()));
            when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        
            when(mockInput.readLine()).thenReturn("Transaction received");

            String transaction = "sourceAccount,destinationAccount,100.0";
            String nonce = MACUtil.generateNonce();
            String encodedKey = Base64.getEncoder().encodeToString(new byte[16]);
            String receivedMAC = MACUtil.generateMAC(transaction, nonce, new SecretKeySpec(new byte[16], "HmacSHA512"));
        
            when(mockInput.readLine()).thenReturn(transaction, nonce, encodedKey, receivedMAC);
        
            String[] parts = transaction.split(",");
            assertEquals(3, parts.length, "Transaction format should be valid");
        
            Transaction newTransaction = new Transaction();
            newTransaction.setSourceAccount(parts[0]);
            newTransaction.setDestinationAccount(parts[1]);
            newTransaction.setAmount(Double.parseDouble(parts[2]));
        
            assertEquals("sourceAccount", newTransaction.getSourceAccount());
            assertEquals("destinationAccount", newTransaction.getDestinationAccount());
            assertEquals(100.0, newTransaction.getAmount());
        }
        
        @Test
        public void testInvalidTransaction() throws Exception {
            Socket mockSocket = mock(Socket.class);
            BufferedReader mockInput = mock(BufferedReader.class);
        
            when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("Invalid transaction format\n".getBytes()));
            when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        
            when(mockInput.readLine()).thenReturn("Invalid transaction format");
        
            String transaction = "sourceAccount,destinationAccount";
            String nonce = MACUtil.generateNonce();
            String encodedKey = Base64.getEncoder().encodeToString(new byte[16]);
            String receivedMAC = MACUtil.generateMAC(transaction, nonce, new SecretKeySpec(new byte[16], "HmacSHA512"));
        
            when(mockInput.readLine()).thenReturn(transaction, nonce, encodedKey, receivedMAC);
        
            String[] parts = transaction.split(",");
            assertNotEquals(3, parts.length, "Transaction format should be invalid");
        }

        @Test
        public void testTransactionMITMAttack() throws Exception {
            Socket mockSocket = mock(Socket.class);
            BufferedReader mockInput = mock(BufferedReader.class);
        
            when(mockSocket.getInputStream()).thenReturn(new ByteArrayInputStream("Transaction received\n".getBytes()));
            when(mockSocket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        
            when(mockInput.readLine()).thenReturn("Transaction received");
        
            String transaction = "sourceAccount,destinationAccount,100.0";
            String nonce = MACUtil.generateNonce();
            String encodedKey = Base64.getEncoder().encodeToString(new byte[16]);
            String receivedMAC = MACUtil.generateMAC(transaction, nonce, new SecretKeySpec(new byte[16], "HmacSHA512"));
        
            String modifiedTransaction = "sourceAccount,destinationAccount,100000.0";
            String modifiedMAC = MACUtil.generateMAC(modifiedTransaction, nonce, new SecretKeySpec(new byte[16], "HmacSHA512"));
        
            when(mockInput.readLine()).thenReturn(modifiedTransaction, nonce, encodedKey, modifiedMAC);
        
            String[] parts = modifiedTransaction.split(",");
            assertEquals(3, parts.length, "Transaction format should be valid");
        
            boolean isMACValid = MACUtil.verifyMAC(modifiedTransaction, nonce, new SecretKeySpec(new byte[16], "HmacSHA512"), receivedMAC);
            assertFalse(isMACValid, "MAC should be invalid due to Man in the Middle attack");
        }

        private List<User> simulateRepositoryResponse(){

            String username = "testUser";
            String password = "Strong1@Password";
    
            // Generating a random salt
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            String saltBase64 = Base64.getEncoder().encodeToString(salt);

            String hash = getHashPassowrd(password, saltBase64);

            List<User> users = new ArrayList<>();
            User user = new User();
            user.setUsername(username);
            user.setHash(hash);
            user.setSalt(saltBase64);
            users.add(user);
    
            return users;
    
        }

        private String getHashPassowrd(String password, String salt){
            // Argon2 setup for password hashing
            Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
            int iterations = 10;
            int memory = 65536;
            int parallelism = 1;
            // Hash password
            return argon2.hash(iterations, memory, parallelism, (password + salt).toCharArray());
        }



    }
