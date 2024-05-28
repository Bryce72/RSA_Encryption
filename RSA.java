import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.sql.Time;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;

public class RSA
{

    // (didnt use this method)Sieve of Eratosthenes - used to generate prime numbers (will randomize later)


    /** Immutable Class BigInteger is used to generate a prime number of about 2048 bit length
     *  "The probability that a BigInteger returned by this method is composite does not exceed 2^-100"
     *
     *
     *
     * @return BigInteger Prime value that is randomized @ 2048 bit length -- will later change this so i can automate different key sizes
     */
    public static BigInteger primeGenerator(int keyLength)
    {
       return BigInteger.probablePrime(keyLength, new Random());
    } // changed this to make a parameter so i can automate tests, standard would be to use 2048


    /**
     *                m^e mod(n)
     *
     * @param message - String type to be encrypted
     * @param e - BigInteger type - set at 65537
     * @param n - BigInteger type - calculated by p * q
     * @return - Returns a BigInteger type array of encrypted values.
     */
    public static BigInteger[] encryptMessage(String message, BigInteger e, BigInteger n)
    {
        byte[] b = message.getBytes(StandardCharsets.US_ASCII);  // converting String to Ascii byte sequence
        BigInteger[] encryptionHere = new BigInteger[b.length];  // use this BigInteger array to store encypted BigInteger type
        //encryption
        for (int i = 0; i < b.length; i++)
        {
            // need to take each element in type byte array and perform modulus operation on a BigInteger type array
            BigInteger m = BigInteger.valueOf(b[i]);
            encryptionHere[i] = m.modPow(e, n); //o
        }
        return encryptionHere;
    }


    /**
     *                  c^d mod(n)
     *
     * @param encryptionHere - BigInteger type array of encrypted values
     * @param n - BigInteger type - calculated by  p * q
     * @param d - BigInteger type - private key
     * @return - Returns String of plain text
     */
    public static String decryptMessage(BigInteger[] encryptionHere, BigInteger n, BigInteger d)
    {
        //decryption
        BigInteger[] decryptionHere = new BigInteger[encryptionHere.length];
        byte[] decryptionByte =  new byte[decryptionHere.length];
        for(int i = 0 ; i < encryptionHere.length; i++)
        {
            //  encryptionHere[i] == c is each letter in string (including spaces) encrypted
            // c^d mod(n)
            BigInteger plainText =  encryptionHere[i].modPow(d, n); // that d is the secret key
            decryptionHere[i] = plainText;
            decryptionByte[i] = decryptionHere[i].byteValue();
        }
        String decryptedMessage = new String(decryptionByte, StandardCharsets.US_ASCII);
        return decryptedMessage;

    }




    // CSV stuff

    public static void writeToCSV(String filename, String message, int keyLength, Duration timeEncrypt, Duration timeDecrypt)
    {
        try (FileWriter fileWriter = new FileWriter(filename, true);
             PrintWriter printWriter = new PrintWriter(fileWriter)) {
            printWriter.printf("%d,%s,%d,%d,%d%n", keyLength, message, message.length(), timeEncrypt.toMillis(), timeDecrypt.toMillis());
        } catch (IOException e) {
            System.err.println("Error writing to CSV file: " + e.getMessage());
        }
    }



    // for constant key length but different message size
    public static void generateMessagesAndTest(int maxLength, BigInteger e, BigInteger n, BigInteger d)
    {
        for (int i = 1; i <= maxLength; i++) {
            StringBuilder message = new StringBuilder();
            for (int j = 0; j < i; j++) {
                char randomChar = (char) ('a' + new Random().nextInt(26)); // generates a random character from 'a' to 'z'
                message.append(randomChar);
            }

            Instant startEncrypt = Instant.now();
            BigInteger[] encryptedMessage = encryptMessage(message.toString(), e, n);
            Instant endEncrypt = Instant.now();
            Duration timeEncrypt = Duration.between(startEncrypt, endEncrypt);

            Instant startDecrypt = Instant.now();
            String decryptedMessage = decryptMessage(encryptedMessage, n, d);
            Instant endDecrypt = Instant.now();
            Duration timeDecrypt = Duration.between(startDecrypt, endDecrypt);

            writeToCSV("rsa_times_constant_key.csv", message.toString(), n.bitLength(), timeEncrypt, timeDecrypt);
        }
    }


    public static void writeKeyGenTimeToCSV(String filename, int keyLength, Duration timeKeyGen)
    {
        try (FileWriter fileWriter = new FileWriter(filename, true);
             PrintWriter printWriter = new PrintWriter(fileWriter))
        {
            printWriter.printf("%d,%d%n", keyLength, timeKeyGen.toMillis());
        } catch (IOException e) {
            System.err.println("Error writing to CSV file: " + e.getMessage());
        }
    }

    //for different key length but constant message length
    public static void generateKeysAndTest(String message, int[] keyLengths)
    {
        for (int keyLength : keyLengths)
        {
            int updatedKeyLength = keyLength / 2;

            Instant startKeyGen = Instant.now();
            BigInteger p = primeGenerator(updatedKeyLength);
            BigInteger q = primeGenerator(updatedKeyLength);
            while (p.equals(q)) {
                q = primeGenerator(updatedKeyLength);
            }
            BigInteger n = p.multiply(q);
            BigInteger pminusOne = p.subtract(BigInteger.valueOf(1));
            BigInteger qminusOne = q.subtract(BigInteger.valueOf(1));
            BigInteger phi = pminusOne.multiply(qminusOne);
            BigInteger e = BigInteger.valueOf(65537);
            BigInteger d = e.modInverse(phi);
            Instant endKeyGen = Instant.now();
            Duration timeKeyGen = Duration.between(startKeyGen, endKeyGen);

            Instant startEncrypt = Instant.now();
            BigInteger[] encryptedMessage = encryptMessage(message, e, n);
            Instant endEncrypt = Instant.now();
            Duration timeEncrypt = Duration.between(startEncrypt, endEncrypt);

            Instant startDecrypt = Instant.now();
            String decryptedMessage = decryptMessage(encryptedMessage, n, d);
            Instant endDecrypt = Instant.now();
            Duration timeDecrypt = Duration.between(startDecrypt, endDecrypt);

            writeToCSV("rsa_times_varied_keys.csv", message, keyLength, timeEncrypt, timeDecrypt);
            writeKeyGenTimeToCSV("rsa_keygen_times.csv", keyLength, timeKeyGen);
        }
    }


    public static void main(String[] args) {

        // needed to move this to the top so I can accomodate the automated testing with inputting varrying key lengths
        System.out.println("Welcome to the RSA encryptor!");
        Scanner scan = new Scanner(System.in);
        System.out.println("Start by typing in a message you would like RSA encryption applied to: ");
        String message = scan.nextLine();
        System.out.println("Now type in the bit length you'd like the RSA key to generate; NIST recommends 4096 bit");
        int keyLengthInput = scan.nextInt();
        if(keyLengthInput > 4096 || keyLengthInput < 1)
        {
            System.out.println("only use; 1 - 4096");
            keyLengthInput = scan.nextInt();
        }


        // need to divide the input into two so i can generate the two prime numbers
        int updatedKeyLength = keyLengthInput/2;


        // Step 1: Set prime numbers. - These two cannot be equal.
        BigInteger p = primeGenerator(updatedKeyLength);
        BigInteger q = primeGenerator(updatedKeyLength);

        while(p.equals(q))
        {
            q = primeGenerator(updatedKeyLength);
        }

        // Step 2: Calculate key values --- e and n are public while d is private.
        BigInteger n = p.multiply(q); // generates a 4096 bit n value

        // find phi = (p-1)(q-1)
        BigInteger pminusOne = p.subtract(BigInteger.valueOf(1));
        BigInteger qminusOne = q.subtract(BigInteger.valueOf(1));
        BigInteger phi = pminusOne.multiply(qminusOne);

        // Choose e such that 1 < e < phi and gcd(e,phi) = 1
        BigInteger e  = BigInteger.valueOf(65537); // this is commonly used for e

        // find d (private key), such that e * d mod(phi) = 1
        BigInteger d = e.modInverse(phi); // this is kept secret


        /**
         * To summarize up until here...
         *  Our public key is: e, n
         *  Out private key is: d
         *
         *
         * -- Soon we will denote m = message (plain text) and c = cipher text
         *
         *  in order to encrypt we need to: m^e mod(n)
         *  in order to decrypt we need to: c^d mod(n)
         */

        BigInteger[] encryptedMessageComplete = null;


        Duration timeEncrypt = null;
        Duration timeDecrypt = null;
        while(true)
        {
            System.out.println("1. Encrypt your message \n" +
                               "2. Decrypt your message \n" +
                               "3. Show public key \n" +
                               "4. Show private key \n" +
                               "5. Show me the time it takes to Encrypt \n" +
                               "6. Show me the time it takes to Decrypt \n" +
                               "7. Export automated test (constant key length, different message length) to CSV \n" +
                               "8.Export automated test (constant message length, different key length) to CSV \n \n" +
                               "9. Exit\n" +
                               "Enter your choice 1-8...");
            int choice = scan.nextInt();
            scan.nextLine();
            switch (choice) {
                case 1:
                    Instant start = Instant.now();
                    encryptedMessageComplete = encryptMessage(message, e, n);
                    Instant end = Instant.now();
                    timeEncrypt = Duration.between(start, end);
                    System.out.println("Encrypted Message (Each letter is encrypted): " + Arrays.toString(encryptedMessageComplete));
                    break;

                case 2:
                    if (encryptedMessageComplete == null) {
                        System.out.println("You need to encrypt a message first.");
                    } else {
                        Instant startdecry = Instant.now();
                        String decryptedMessage = decryptMessage(encryptedMessageComplete, n, d);
                        Instant enddecry = Instant.now();
                        timeDecrypt = Duration.between(startdecry, enddecry);
                        System.out.println("Decrypted Message: " + decryptedMessage);
                    }
                    break;

                case 3:
                    System.out.println("Public Key (e, n): (" + e + ", " + n + ")");
                    break;

                case 4:
                    System.out.println("Private Key (d): " + d);
                    break;

                case 5:
                    if(timeEncrypt == null)
                    {
                        System.out.println("Gota encrypt it first!");
                    }
                    else
                    {
                        System.out.println("Time it takes to encrypt: " + timeEncrypt.toMillis() + " milliseconds");
                        System.out.println("Using " + encryptedMessageComplete.length + " characters of encryption!");
                    }
                    break;


                case 6:
                    if(timeEncrypt == null)
                    {
                        System.out.println("Gota decrypt it first!");
                    }
                    else
                    {
                        System.out.println("Time it takes to decrypt: " + timeDecrypt.toMillis() + " milliseconds");
                    }
                    break;


                case 7:
                    System.out.println("Enter the maximum message length for automated testing(!only run once per session!): ");
                    int maxLength = scan.nextInt();
                    generateMessagesAndTest(maxLength, e, n, d);
                    System.out.println("Automated testing complete. Results saved to CSV.");
                    break;

                case 8:
                    System.out.println("Enter the key lengths for automated testing (comma separated, e.g., 1024,2048,4096): ");
                    String keyLengthsInput = scan.nextLine();
                    String[] keyLengthStrings = keyLengthsInput.split(",");
                    int[] keyLengths = new int[keyLengthStrings.length];
                    for (int i = 0; i < keyLengthStrings.length; i++) {
                        keyLengths[i] = Integer.parseInt(keyLengthStrings[i]);
                    }
                    generateKeysAndTest(message, keyLengths);
                    System.out.println("Automated testing with different key lengths complete. Results saved to CSV.");
                    break;

                case 9:
                    System.out.println("Exiting...");
                    scan.close();
                    System.exit(0);
                    break;

                default:
                    System.out.println("Invalid choice. Please try again.");
            }

        }

    }

}
