// CMPSC 444 - Assignment#2 Password Vault
// Authors:
// Joshua Bonner
// Alyssa Abram
// Ariel Rupp

import java.io.*;
import java.lang.*;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


public class PassKeep {

    public static Scanner sc = new Scanner(System.in);
    public static boolean isFileCreated = false;
    public static PrintWriter pw;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, 
	NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
	UnsupportedEncodingException, InvalidAlgorithmParameterException {

        boolean correctInput = false;
        int userChoice = -1;

        //Create Key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		SecretKey aesKey = keyGen.generateKey();
		Cipher cipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
		
        File passKeep = new File("Password_Keeper.txt");
        isFileCreated = passKeep.exists();
        if (isFileCreated == true){
			decryptFile(cipher, aesKey);
			verifyPassword();
		}

        do {

            do {
                System.out.println("\nWelcome to Password Keeper\n\n"
                        + "Please select from the following options:\n"
                        + "1. Initialize Password Keeper file\n"
                        + "2. Change master password\n"
                        + "3. Add new password\n"
                        + "4. Retrieve password information\n"
                        + "5. Share password information\n"
                        + "6. Exit Password Keeper");
                System.out.print("User Input: ");

                if (sc.hasNextInt()){
                    userChoice = sc.nextInt();
                    correctInput = true;
                }
                else {
                    sc.nextLine();
                    System.out.println("\nIncorrect input, please provide an integer numbered 1 through 6\n");
                }
            } while (correctInput == false);

            switch (userChoice) {

                case 1:
                    createFile();
                    System.out.println("\nFile Initialized with master password: password\n");
                    break;

                case 2:
					if (isFileCreated == false)
						System.out.println("\nFile not created! Please choose option 1");
					else {
						String password;
						String oldPass = "password";
						sc = new Scanner(System.in);
						System.out.println("\nEnter new master password: ");
						password = sc.nextLine();
						changeMasterPassword(password, oldPass);
					}
                    break;

                case 3:
					if (isFileCreated == false)
						System.out.println("\nFile not created! Please choose option 1");
					else
						addUserPasswordCombo();
                    break;

                case 4:
                    if (isFileCreated == false)
                        System.out.println("\nFile not created! Please choose option 1");
                    else
						readFile();
                    break;

                case 5:
                    if (isFileCreated == false)
                        System.out.println("\nFile not created! Please choose option 1");
                    else
                        shareFile(aesKey, cipher);
                    break;

                case 6:
                    System.out.println("\nThank you for using Password Keeper!\n");
					if (isFileCreated == true)
						encryptFile(cipher, aesKey);
                    System.exit(0);
                    break;

                default:
                    System.out.println("\nIncorrect input, please provide an integer numbered 1 through 6\n");
            }

        } while (userChoice != 6);
        System.out.println("\nUnknown Error Occured");
    }

    public static void createFile(){
        try {
            File passKeep = new File("Password_Keeper.txt");

            if(!passKeep.exists()) passKeep.createNewFile();

            pw = new PrintWriter(passKeep);
            pw.println("ID\t\tUSER\t\tPASSWORD\nMaster\t\tMaster\t\tpassword");
            pw.close();
            isFileCreated = true;

        } catch (IOException e) {System.out.println("ERROR CREATING FILE\n");}
    }

	public static void decryptFile(Cipher cipher, SecretKey aesKey) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException
    {
        try{
			// Read in IV and Key from file
            BufferedReader br = new BufferedReader( new FileReader( "Not_Secret_Stuff.txt" ) );
            String ivSTR = br.readLine();
			String secret_key = br.readLine();
            byte[] secret_Key = DatatypeConverter.parseBase64Binary( secret_key );
            byte[] iv = DatatypeConverter.parseBase64Binary( ivSTR );
			
			// Read in encrypted Password Keeper file and store in byte[] cipherText
			// readLine() automatically cuts off new line char
            BufferedReader file = new BufferedReader( new FileReader( "Password_Keeper.txt" ));
            String inputStr = file.readLine();
            file.close();
            byte[] cipherText = DatatypeConverter.parseBase64Binary(inputStr);
			
			// Decrypt cipherText[] and store in a string
			IvParameterSpec receiver_iv = new IvParameterSpec( iv );
            SecretKey receiver_secret = new SecretKeySpec( secret_Key, "AES" );
			Cipher receiver_cipher = Cipher.getInstance( "AES/CBC/PKCS5Padding" );
            receiver_cipher.init( Cipher.DECRYPT_MODE, receiver_secret, receiver_iv );
            String plainText = new String(receiver_cipher.doFinal(cipherText), "UTF-8");
			
			// Write out decrytped ciphertext into Password_Keeper.txt replacing the encrypted file
			FileOutputStream fileOut = new FileOutputStream( "Password_Keeper.txt" );
            fileOut.write(plainText.getBytes());
            fileOut.close();
        }
        catch ( IOException  | BadPaddingException | IllegalBlockSizeException e ) {e.printStackTrace();}
    }
	
	public static void encryptFile(Cipher cipher, SecretKey aesKey) throws InvalidKeyException
    {
        cipher.init(Cipher.ENCRYPT_MODE,aesKey);

        byte[] iv = cipher.getIV();
        byte[] secret = aesKey.getEncoded();

        try
        {
            BufferedReader file = new BufferedReader( new FileReader( "Password_Keeper.txt" ) );
            StringBuffer strBuffer = new StringBuffer(  );
            String line = "";

            while((line = file.readLine()) != null)
            {
                strBuffer.append( line );
                strBuffer.append( '\n' );
            }
            file.close();

            String inputStr = strBuffer.toString();
            byte[] cipherText = cipher.doFinal(inputStr.getBytes("UTF-8"));

            PrintWriter fileOut = new PrintWriter( "Password_Keeper.txt" );
            fileOut.println(DatatypeConverter.printBase64Binary(cipherText));
            fileOut.close();

            File notSecretStuff = new File("Not_Secret_Stuff.txt");
            if(!notSecretStuff.exists()) notSecretStuff.createNewFile();
			
			String IV = DatatypeConverter.printBase64Binary(iv);
			String SECRET = DatatypeConverter.printBase64Binary(secret);
			
			FileOutputStream FileOut = new FileOutputStream("Not_Secret_Stuff.txt");
			FileOut.write(IV.getBytes());
			FileOut.write('\n');
			FileOut.write(SECRET.getBytes());

        }
        catch ( IOException | IllegalBlockSizeException | BadPaddingException e ) {e.printStackTrace();}
    }

	public static void changeMasterPassword(String replaceWith, String type){
		try {
		     BufferedReader file = new BufferedReader(new FileReader("Password_Keeper.txt"));
		     StringBuffer buffer = new StringBuffer();
		     String line = null;

		     while ((line = file.readLine()) != null) {
				buffer.append(line);
				buffer.append('\n');
		     }
		     file.close();
		     String inputStr = buffer.toString();
		    
		     if (type.equals("password"))
			inputStr = inputStr.replace(type, replaceWith);

		     FileOutputStream fileOut = new FileOutputStream("Password_Keeper.txt");
		     fileOut.write(inputStr.getBytes());
		     fileOut.close();
		
		} catch (IOException e) {System.out.println("Something went wrong\n");}
	}

    public static boolean verifyPassword(){
        String password;
        boolean passwordVerified = false;
        String[] str = null;
		int count = 0;

        do {
			
			if (count == 5){
				System.out.println("\nYou aint the real user!");
				System.out.println("You are on time out mister!");
				try {Thread.sleep(10000);} 
				catch (InterruptedException e) {System.out.println("Something went wrong!\n");}
				System.exit(0);
			}
			
            System.out.println("\nEnter master password: ");
            password = sc.nextLine();

            try {
                FileReader fr = new FileReader("Password_Keeper.txt");
                BufferedReader br = new BufferedReader(fr);
                str = br.readLine().split("\t");
                str = br.readLine().split("\t");
                br.close();

            } catch (IOException e) {System.out.println("FAILED TO OPEN FILE\n");}

            if (password.equals(str[4])){
                passwordVerified = true;
                return true;
            }
            else{
				System.out.println("\nWrong Credentials!");
				count++;
			}
            

        } while(!(passwordVerified));
        return false;
    }

    public static void readFile(){
        try {
            FileReader fr = new FileReader("Password_Keeper.txt");
            BufferedReader br = new BufferedReader(fr);

            String str;
            System.out.println("\nPASSWORD INFORMATION:\n" +
					"________________________________________");
            while ((str = br.readLine()) != null)
                System.out.println(str);
	    
            br.close();

        } catch (IOException e) {System.out.println("FAILED TO OPEN FILE\n");}

    }
	
    //https://beginnersbook.com/2014/05/how-to-copy-a-file-to-another-file-in-java/
    public static void shareFile( SecretKey aesKey, Cipher cipher) throws IOException, NoSuchAlgorithmException, 
	NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
	UnsupportedEncodingException, InvalidAlgorithmParameterException {
        FileInputStream inStream = null;
        FileOutputStream outStream = null;
        String selection;
        String brString;

        try{

            File inFile = new File("Password_Keeper.txt");
            File outFile = new File ("Password_Keeper_Share.txt");

            inStream = new FileInputStream( inFile );
            outStream = new FileOutputStream( outFile );

            FileReader fr = new FileReader("Password_Keeper.txt");
            BufferedReader br = new BufferedReader(fr);

            String[] tokens;
            String id = null, password = null, user = null, str = null, idCompare = null;

            sc.nextLine();
            System.out.print( "\nSelect (by id) which username/password combination you want to share: " );
            selection = sc.nextLine();

            while ((brString = br.readLine()) != null)
            {
                tokens = brString.split("\t");
                if(selection.equals(tokens[0])){
                    id = tokens[0];
                    user = tokens[2];
                    password = tokens[4];
                    break;
                }
            }

			String inputStr = id + "\t\t" + user + "\t\t" + password;
			
			cipher.init(Cipher.ENCRYPT_MODE, aesKey);
			byte[] ciphertext = cipher.doFinal(inputStr.getBytes("UTF-8"));

            pw = new PrintWriter(outFile);
            pw.println(DatatypeConverter.printBase64Binary(ciphertext));
            pw.close();

            System.out.println( "\nFile: [Password_Keeper_Share.txt] saved successfully for sharing." );
        }
        catch(IOException e){System.out.println("Failed to share file");}

        inStream.close();
        outStream.close();
    }

    public static void addUserPasswordCombo()
    {
        String correctInput;
        boolean flag = false;	

        try
        {
	    String textToAppend = null;
	    String ID = null;
	    String User = null;
	    String Password = null;

            //https://howtodoinjava.com/java/io/java-append-to-file/
            BufferedWriter writer = new BufferedWriter( new FileWriter("Password_Keeper.txt", true) );

            while(!flag)
            {
				System.out.println( "\nEnter ID: ");
				sc.nextLine();
				ID = sc.nextLine();
				System.out.println("\nEnter User: ");
				User = sc.nextLine();
                System.out.println( "\nDo you want a computer generated random password for this account? Enter 1 for yes or 0 for no." );
                correctInput = sc.nextLine();
		
                if(correctInput.equals( "1" ) )
                {
					Password = randomPassword();
                    flag = true;
                }
                else if (correctInput.equals( "0" ))
                {
					System.out.print("Enter password: ");
					Password = sc.nextLine();
                    flag = true;
                }
                else
                {
                    flag = false;
                }
            }

			textToAppend = ID + "\t\t" + User + "\t\t" + Password + "\n";
            writer.write(textToAppend);
            writer.close();
        }
        catch ( Exception e){System.out.println( "File failed to open." );}
    }

    //https://www.baeldung.com/java-generate-secure-password
    public static Stream<Character> getRandomSpecialChars( int count)
    {
        Random random = new SecureRandom(  );
        IntStream specialChars = random.ints(count, 33, 45);
        return specialChars.mapToObj( data ->(char) data );
    }

    public static Stream<Character> getRandomNumbers(int count)
    {
        Random random  = new SecureRandom(  );
        IntStream randomNumbers = random.ints(count, 48, 57);
        return randomNumbers.mapToObj( data ->(char) data );
    }

    public static Stream<Character> getRandomAlphabets (int count, boolean upperCase)
    {
        Random random = new SecureRandom(  );
        IntStream randomAlphabets;
        if(upperCase)
        {
            randomAlphabets = random.ints(count, 65, 90);
        }
        else
        {
            randomAlphabets = random.ints(count, 97, 122);
        }
        return randomAlphabets.mapToObj(data -> (char) data);
    }


    public static String randomPassword()
    {
        Stream<Character> passwordStream = Stream.concat(getRandomNumbers(2), Stream.concat(getRandomSpecialChars(2),
                        Stream.concat(getRandomAlphabets(2, true), getRandomAlphabets(10, false))));
        List<Character> charList = passwordStream.collect( Collectors.toList());
        Collections.shuffle( charList );
        return charList.stream().collect( StringBuilder::new, StringBuilder::append, StringBuilder::append ).toString();
    }
}



/*------------------------------------------------------------------------------
Questions:
2) Description of how we are using symmetric key encryption, including how we are sharing the keys used in 
   encrypting exported passwords.
   	
   	For the Symmetric Key encryption, we have our main file with the master password and user passwords, then we have the
	IV And Secret Key encrypted in a separate file, that we utilize in the program to decrypt our password file.

	When we encrypt the shared password file, 

3) What are the revisied list of vulnerabilities?
	If the program is left running, the password file is left available to anyone to open and view it, hence the file is
	still easily accessible against the user's will. 

	As written, there is now a short wait time between the user incorrectly inputting passwords to gain access to the
	program. So this is still vulnerable to brute force attacks, it will just take longer as the program will have a timer
	and close after 5 incorrect password attempts. 

	The random password generation has recieved an upgrade requiring 2 uppercase letters, 10 lowercase letters, 2 numbers,
	and 2 special characters. Once the letters have been selected, they are then shuffled. Therefor, to our knowledge, 
	the random password is no longer insecure as it had been.

	The random password is hard coded to be 16 characters long, however if the user decides to create their own password, 
	the user can still make a bad decision to not follow these requirements as the random password generator follows. 
	Additionally, the user should not be allowed to have the same password for each login.

	Once the user has logged in and the programming is running, if the user walks away not only can an adversary
	come up to the computer and get into the unencrypted password file, the program does not ask for the password other
	than at the very beginning of the program. 

*/
