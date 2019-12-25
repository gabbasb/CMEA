package com.edb.cmea;

import java.io.*;

import java.math.BigInteger;

import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;


import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.KeyFactory;
import java.security.spec.*;

import java.nio.charset.StandardCharsets;

import com.didisoft.pgp.*;
import com.didisoft.pgp.exceptions.*;


import java.sql.*;
import java.util.Calendar;
import java.net.URL;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;


// build
// mvn package
// run
// java -cp target/CMEA-1.0-SNAPSHOT.jar:
//            /home/abbas/.m2/repository/junit/junit/3.8.1/junit-3.8.1.jar:
//            /home/abbas/.m2/repository/org/postgresql/postgresql/42.2.5/postgresql-42.2.5.jar:
//            /home/abbas/Projects/pgconf_2020/didisoft/Library/bcpg-lw-jdk15on-1.59.jar:
//            /home/abbas/Projects/pgconf_2020/didisoft/Library/bcprov-lw-jdk15on-1.59.jar:
//            /home/abbas/Projects/pgconf_2020/didisoft/Library/pgplib-3.2.1.jar 
//            com.edb.cmea.App read-messages

// Since we are using trial version of DidiSoft PGP Library for Java
// it is not provided as a maven repo.
// Instead the pom.xml file adds dependency to the local file system
// Before building make sure that the file system paths given in
// the dependency are correct.

public class App 
{
	private static final String ALGORITHM = "AES";
	private static final String CIPHER = "AES/CBC/PKCS5PADDING";
	private static final String m_url = "jdbc:postgresql://127.0.0.1:5432/test_db";
	private static final String m_user = "abbas";
	private static final String m_password = "abc123";
	private static final int CERTAINTY = 12;
	private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(0x10001);

	public static Connection m_pg = null;
	
	public static String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X ", b));
		}
		return sb.toString();
	}

	public static int arrayContains(String[] optionsArray, String optionPassed)
	{
		int size = optionsArray.length;
		for (int i = 0; i < size; i++)
		{
			if (optionsArray[i].equals(optionPassed)) {
				return i;
			}
		}
		return -1;
	}

	public static String getUserInput(String inputMsg) {
		Scanner scanner = new Scanner(System.in);
		System.out.print(inputMsg);
		return scanner.nextLine();
	}

	static String getRandomString(int n) {
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    + "0123456789"
                                    + "abcdefghijklmnopqrstuvxyz";

        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            int index = (int)(AlphaNumericString.length() * Math.random());
            sb.append(AlphaNumericString.charAt(index));
        }

        return sb.toString(); 
    }

    static String genKeyPair(String keyFileName) throws PGPException, FileNotFoundException, IOException {
		String keyPwd = "whatever";

		PGPKeyPair keyPair = PGPKeyPair.generateRsaKeyPair(2048, keyFileName, keyPwd);
		keyPair.exportPublicKey("/tmp/" + keyFileName + ".public", true);
		keyPair.exportPrivateKey("/tmp/" + keyFileName + ".private", true);
		return new String (Files.readAllBytes(Paths.get("/tmp/" + keyFileName + ".public")));
	}

	public static int addUser() {
		String userName;
		String userPublicKey = "";
		String SQL = "INSERT INTO cmea.tbl_users(u_name, u_public_key) VALUES(?,?)";

		int count = 0;

		try {
			PreparedStatement insUser = m_pg.prepareStatement(SQL);
			count = 0;

			// a) Select a username.
			while (true) {
				userName = getUserInput("Enter your desired username (q to quit):");
				if (userName.length() <= 1) {
					insUser.close();
					return count;
				}

				insUser.setString(1, userName);
				try {
					// d) Generate a public-private key pair.
					// e) Store the key pair in the file system.
					userPublicKey = genKeyPair(userName);
				} catch (Exception e) {
					e.printStackTrace();
				}
				if (userPublicKey.length() <= 1)
					return count;
				insUser.setString(2, userPublicKey);

				// f) Insert the new user in the table tbl_users.
				insUser.executeUpdate();
				count++;
			}
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}
		return count;
	}

	public static String rightPad(String src, int count, char pad) {
		StringBuilder sb = new StringBuilder(src);
		int reqCount = count - src.length();
		for(int i = reqCount; i >= 0; i--) {
			sb.append(pad);
		}
		return sb.toString();
	}

	public static String getUserPrivateKey(String username) throws FileNotFoundException, IOException {
		return new String (Files.readAllBytes(Paths.get("/tmp/" + username + ".private")));
	}

	public static int getUserID(String username) {
		int userID = 0;
		try {
			Statement st = m_pg.createStatement();
			ResultSet rs = st.executeQuery("SELECT u_id FROM cmea.tbl_users WHERE u_name = '" + username + "';");
			while (rs.next())
			{
				userID = rs.getInt(1);
			}
			rs.close();
			st.close();
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}
		return userID;
	}

	public static int addFriend() {
		// a) Enter username.
		String username = getUserInput("Enter your username (q to quit):");
		if (username.length() <= 1)
			return 0;

		// d) Confirm username exists in tbl_users.
		int myUserID = getUserID(username);
		if (myUserID <= 0)
			return 0;

		// f) List available users.
		System.out.println("Available Users:");
		System.out.println("  ID     |    Username");
		System.out.println("---------+------------");
		try {
			Statement st = m_pg.createStatement();
			ResultSet rs = st.executeQuery("SELECT u_id, u_name FROM cmea.tbl_users WHERE u_id != " + myUserID + " ORDER BY u_id;");
			while (rs.next())
			{
				System.out.println("  " + rightPad(rs.getString(1), 6, ' ') + "|  " + rs.getString(2));
			}
			rs.close();
			st.close();
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}
		
		int friendID = 0;
		PublicKey friendPublicKey = null;
		String SQL = "SELECT cmea.addFriend(?,?,?)";

		int count = 0;

		try {
			PreparedStatement insFriend = m_pg.prepareStatement(SQL);
			count = 0;

			while (true) {
				// g) Select a friend.
				String tmp = getUserInput("Enter ID of user to make friend (0 to quit):");
				friendID = Integer.parseInt(tmp);
				if (friendID == 0) {
					insFriend.close();
					return count;
				}
				// i) Generate a secret key.
				String secretKey = getRandomString(32);
				
				insFriend.setInt(1, myUserID);
				insFriend.setInt(2, friendID);
				insFriend.setString(3, secretKey);

				// The function addFriend performs these steps:
				// h) Get own and friend’s public key from the tbl_users
				// j) Encrypt the secret key using your own public key and store in f_mek_for_sending.
				// k) Encrypt the secret key using friend’s public key and store in f_mek_for_reading.
				// l) Insert row in tbl_friends.

				ResultSet rs = insFriend.executeQuery();
				while (rs.next())
				{
					int res = rs.getInt(1);
				}
				rs.close();

				count++;
			}
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}
		return count;
	}

	public static int sendMsg() {
		// a) Enter username.
		String username = getUserInput("Enter your username (q to quit):");
		if (username.length() <= 1)
			return 0;

		// d) Confirm username exists in tbl_users.
		int myUserID = getUserID(username);
		if (myUserID <= 0)
			return 0;

		// e) Load private key pair from file.
		String userPrivateKey = "";
		try {
			userPrivateKey = getUserPrivateKey(username);
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
		}

		// f) List available friends.
		System.out.println("Available Friends:");
		System.out.println("  ID     |    Friend name");
		System.out.println("---------+---------------");
		try {
			Statement st = m_pg.createStatement();
			ResultSet rs = st.executeQuery("SELECT f_to_u_id, u_name FROM cmea.tbl_users, cmea.tbl_friends WHERE u_id = f_to_u_id AND f_from_u_id = " + myUserID + " ORDER BY 1;");
			while (rs.next())
			{
				System.out.println("  " + rightPad(rs.getString(1), 6, ' ') + "|  " + rs.getString(2));
			}
			rs.close();
			st.close();
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}

		// g) Select a friend to send message to.
		int friendID = 0;
		String tmp = getUserInput("Enter ID of the friend to send the message to (0 to quit):");
		friendID = Integer.parseInt(tmp);
		if (friendID == 0) {
			return 0;
		}

		String SQL = "SELECT cmea.sendMsg(?, ?, ?, ?);";
		int count = 0;
		try {
			PreparedStatement insMessage = m_pg.prepareStatement(SQL);
			count = 0;

			while (true) {
				// j) Enter message to send.
				String msgToSend = getUserInput("Enter the message (q to quit):");
				if (msgToSend.length() <= 1) {
					insMessage.close();
					return count;
				}

				insMessage.setInt(1, myUserID);
				insMessage.setInt(2, friendID);
				insMessage.setString(3, userPrivateKey);
				insMessage.setString(4, msgToSend);

				// Function sendMsg performs all these steps
				// h) Get the message encryption key (f_mek_for_sending) from tbl_friends.
				// i) Decrypt f_mek_for_sending using your private key to get secret key.
				// k) Encrypt message using secret key.
				// l) Insert row in tbl_messages.
				ResultSet rs = insMessage.executeQuery();
				while (rs.next())
				{
					int res = rs.getInt(1);
				}
				rs.close();
				count++;
			}
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}
		return count;
	}

	public static int readMsg() {
		// a) Enter username.
		String username = getUserInput("Enter your username (q to quit):");
		if (username.length() <= 1)
			return 0;

		// d) Confirm username exists in tbl_users.
		int myUserID = getUserID(username);
		if (myUserID <= 0)
			return 0;

		// e) Load private key pair from file.
		String userPrivateKey = "";
		try {
			userPrivateKey = getUserPrivateKey(username);
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
		}

		// f) List available message count from all friends.
		System.out.println("Available Messages:");
		System.out.println("  ID     |    Friend name   |  Message Count");
		System.out.println("---------+------------------+---------------");
		try {
			Statement st = m_pg.createStatement();
			ResultSet rs = st.executeQuery("SELECT cmea.getSenderID (m_f_id) sender_id, cmea.getSenderName(m_f_id) sender_name, count(m_f_id) msg_count FROM cmea.tbl_messages WHERE m_f_id IN ( SELECT f_id FROM cmea.tbl_friends WHERE f_to_u_id = " + myUserID + ") GROUP BY m_f_id ORDER BY 2");
			while (rs.next())
			{
				System.out.println("  " + rightPad(rs.getString(1), 6, ' ') + "|  " + rightPad(rs.getString(2), 15, ' ') +  "|  " + rs.getString(3));
			}
			rs.close();
			st.close();
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}

		int count = 0;

		while (true) {
			int friendID;
			System.out.println();
			System.out.println();

			// g) Select a friend to read messages from.
			String tmp = getUserInput("Enter ID of the friend to read the message from (0 to quit):");
			friendID = Integer.parseInt(tmp);
			if (friendID == 0) {
				return count;
			}

			// Function readMsg performs these steps
			// h) Get the message encryption key (f_mek_for_reading) from tbl_friends.
			// i) Decrypt f_mek_for_reading using your private key to get secret key.
			// j) List all messages from the selected friend by decrypting the messages using secret key.
			String SQL = "SELECT * FROM cmea.readMsg(?, ?, ?);";

			System.out.println("Messages:");
			System.out.println("  ID   |   Friend Name    |    Sent On                  |    Message   ");
			System.out.println("-------+------------------+-----------------------------+------------------------------------");
			try {
				PreparedStatement readMessage = m_pg.prepareStatement(SQL);
				readMessage.setInt(1, myUserID);
				readMessage.setInt(2, friendID);
				readMessage.setString(3, userPrivateKey);

				ResultSet rs = readMessage.executeQuery();
				while (rs.next())
				{
					count++;
					System.out.println("  " + rightPad(rs.getString(1), 4, ' ') + "|  " + rightPad(rs.getString(2), 15, ' ') + "|  " + rightPad(rs.getString(3), 26, ' ') + "|  " + rs.getString(4));
				}
				rs.close();
				readMessage.close();
			} catch (SQLException ex) {
				System.out.println(ex.getMessage());
			}
		}
	}

	private static boolean connectWithDb() {
		try {
			Class.forName("org.postgresql.Driver");
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Class Not Found : " + e.getMessage()); 
			return false;
		}

		try {
			m_pg = DriverManager.getConnection(m_url,
												m_user,
												m_password);
		} catch (SQLException e) {
			System.err.format("SQL State: %s\n%s", e.getSQLState(), e.getMessage());
			return false;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

    public static void main( String[] args )
    {
		String[] options = {"add-user", "add-friend", "send-messages", "read-messages"};
		final int ADD_USER = 0;
		final int ADD_FRIEND = 1;
		final int SEND_MSG = 2;
		final int READ_MSG = 3;
		int count = 0;
	
		if (args.length < 1) {
			System.out.println("The program expects either add-user, add-friend, send-messages or read-messages as command line argument");
			return;
		}
		
		int optionIndex = arrayContains(options, args[0]);
		
		if (optionIndex < 0) {
			System.out.println("The program expects either add-user, add-friend, send-messages or read-messages as command line argument");
			return;
		}

		connectWithDb();

		switch (optionIndex) {
			case ADD_USER:
				count = addUser();
				System.out.println("Added " + count + " users");
			break;
			case ADD_FRIEND:
				count = addFriend();
				System.out.println("Added " + count + " friends");
			break;
			case SEND_MSG:
				count = sendMsg();
				System.out.println("Sent " + count + " messages");
			break;
			case READ_MSG:
				count = readMsg();
				System.out.println("Read " + count + " messages");
			break;
		}
    }
}
