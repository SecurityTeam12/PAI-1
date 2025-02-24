package secteam12.pai1.server;

import org.springframework.security.crypto.bcrypt.BCrypt;
import java.security.SecureRandom;

public class PassUtils {
    // Genera una contraseña aleatoria de 12 caracteres
    public static String generateRandomPassword() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();

        for (int i = 0; i < 12; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }

        return password.toString();
    }

    // Genera un salt aleatorio usando BCrypt
    public static String generateSalt() {
        return BCrypt.gensalt(12);
    }

    // Hashea la contraseña con el salt usando BCrypt
    public static String hashPassword(String password, String salt) {
        return BCrypt.hashpw(password, salt);
    }

    // Verifica si la contraseña ingresada es válida
    public static boolean verifyPassword(String inputPassword, String storedHash) {
        return BCrypt.checkpw(inputPassword, storedHash);
    }

    public static void main(String[] args) {
        // Ejemplo de uso:
        String password = generateRandomPassword();
        String salt = generateSalt();
        String hashedPassword = hashPassword(password, salt);

        System.out.println("Contraseña generada: " + password);
        System.out.println("Salt generado: " + salt);
        System.out.println("Hash almacenado: " + hashedPassword);

        // Simular verificación de contraseña
        boolean isValid = verifyPassword(password, hashedPassword);
        System.out.println("¿La contraseña es válida?: " + isValid);
    }
}
