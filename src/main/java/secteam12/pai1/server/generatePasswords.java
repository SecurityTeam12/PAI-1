package secteam12.pai1.server;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Random;

public class generatePasswords {
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+=<>?/";
    private static final Random RANDOM = new SecureRandom();

    public static String generatePassword(int length) {
        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            password.append(CHARACTERS.charAt(RANDOM.nextInt(CHARACTERS.length())));
        }
        return password.toString();
    }

    public static void generateSqlInsert(int numUsers, String filePath) {
        try {
            File file = new File(filePath);
            Files.createDirectories(Paths.get(file.getParent())); // Crea la carpeta si no existe

            try (FileWriter writer = new FileWriter(file)) {
                for (int i = 1; i <= numUsers; i++) {
                    String username = "user" + i;
                    String password = generatePassword(12);
                    writer.write("INSERT INTO users (id, username, password) VALUES (" + i + ", '" + username + "', '" + password + "');\n");
                }
            }

            System.out.println("Archivo SQL generado en: " + filePath);
        } catch (IOException e) {
            System.out.println("Error generateSqlInsert: " +  e.getMessage() );
        }
    }

    public static void main(String[] args) {
        String filePath = "src/main/resources/data.sql";
        generateSqlInsert(5, filePath);
        System.out.println("Ejemplo de contraseña generada: " + generatePassword(12));
    }
}
