package engine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

//import CryptoUtils;

public class CryptoUtils {

	static RSAPublicKey pubKey;
	static RSAPrivateKey privKey;
	static SecretKey secretKey;

	public boolean fileExists(String path) {

		File file = new File(path);
		if (file.exists())
			return true;
		else
			return false;
	}

	// génération de paire de clés RSA

	public void generateKeyPairs() {

		KeyPairGenerator keyGen;
		try {

			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keyPair = keyGen.genKeyPair();

			// pubKey generation and storing
			pubKey = (RSAPublicKey) keyPair.getPublic();
			this.storePublicKeyEncoded("pubKeyBanque.key", pubKey);

			// privKey generation and storing

			privKey = (RSAPrivateKey) keyPair.getPrivate();
			this.storePrivateKeyEncoded("privKeyBanque.key", privKey);
			// storePrivKeyKeyStore(privKey);

			System.out.println("pubKey (pubKeyBanque.key): -> "
					+ new String(pubKey.getEncoded()));
			System.out.println("privKey (privKeyBanque.key): -> "
					+ new String(privKey.getEncoded()));

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// Cette méthode permet d'initialiser nos deux clés de type RSA
	void initRSAKeys() {

		if (fileExists("pubKeyBanque.key") && fileExists("pubKeyBanque.key"))
			return;
		else
			generateKeyPairs();

	}

	public static RSAPublicKey getRSAPubKey(byte[] publicExponent,
			byte[] modulus) {

		RSAPublicKey pubKey = null;
		try {
			RSAPublicKeySpec pubKeySpec = null;
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");

			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			BigInteger n = new BigInteger(modulus);
			BigInteger e = new BigInteger(publicExponent);

			pubKeySpec = new RSAPublicKeySpec(n, e);
			pubKey = (RSAPublicKey) kf.generatePublic(pubKeySpec);

		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| InvalidKeySpecException ex) {
			Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
					null, ex);
		}
		return pubKey;
	}

	// ///////////////////// getPrivateKey() /////////////////:
	public static RSAPrivateKey getRSAPrivateKey(byte[] privateExponent,
			byte[] modulus) {

		RSAPrivateKey privKey = null;
		try {
			RSAPrivateKeySpec privKeySpec = null;
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");

			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			BigInteger n = new BigInteger(modulus);
			BigInteger d = new BigInteger(privateExponent);

			privKeySpec = new RSAPrivateKeySpec(n, d);
			privKey = (RSAPrivateKey) kf.generatePrivate(privKeySpec);

		} catch (NoSuchAlgorithmException | NoSuchProviderException
				| InvalidKeySpecException ex) {
			Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
					null, ex);
		}
		return privKey;
	}

	// #################################################################

	// cette méthode permet de retourner le hash d'un message, ce hash sera
	// comparé à celui dans la base de données
	public static String digest(String message) {

		MessageDigest md;
		StringBuffer sb = new StringBuffer();
		try {
			md = MessageDigest.getInstance("MD5");

			md.update(message.getBytes());
			byte[] digest = md.digest();

			for (byte b : digest) {
				sb.append(Integer.toHexString((int) (b & 0xff)));
			}

		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
		}

		System.out.println("digest (" + message + ") : -> " + sb.toString());
		return sb.toString();

	}

	// cette méthode permet de comparer deux strings, elle nous servireapour
	// comparer les données données par l'utilisateur avec celles stockées dans
	// la base de données
	public static boolean compare(String message1, String message2) {

		if (message1.compareTo(message2) == 0) {

			System.out.println("compare (" + message1 + ", " + message2
					+ ") : -> " + true);
			return true;

		}

		else {
			System.out.println("compare (" + message1 + ", " + message2
					+ ") : -> " + true);
			return false;
		}

	}

	// Cette méthode permet de signer un challenge, les deux seront envoyé afin
	// d'assurer l'authenticité du message
	public static String sign1(String challenge, RSAPrivateKey privKey) {

		Signature mySign;
		byte[] byteSignedData = null;
		try {
			mySign = Signature.getInstance("MD5withRSA");
			mySign.initSign(privKey);
			mySign.update(challenge.getBytes());
			byteSignedData = mySign.sign();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("signature (" + challenge + "): -->"
				+ new String(byteSignedData));
		return new String(byteSignedData);

	}

	// Cette méthode permet de signer un challenge, les deux seront envoyé afin
	// d'assurer l'authenticité du message
	public static byte[] sign2(String challenge, RSAPrivateKey privKey) {

		Signature mySign;
		byte[] byteSignedData = null;
		try {
			mySign = Signature.getInstance("MD5withRSA");
			mySign.initSign(privKey);
			mySign.update(challenge.getBytes());
			byteSignedData = mySign.sign();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("signature (" + challenge + "): -->"
				+ new String(byteSignedData));
		return byteSignedData;

	}

	// Cette méthode prend en paramètres un challenge et sa signature et vérifie
	// l'authenticité de cett dernière
	public static boolean verify(String challenge, String signature, RSAPublicKey pubKey) throws Exception {

		Signature myVerifySign;
		myVerifySign = Signature.getInstance("MD5withRSA");

		myVerifySign.initVerify(pubKey);
		myVerifySign.update(challenge.getBytes());

		boolean verifySign = myVerifySign.verify(signature.getBytes());
		if (verifySign == false) {
			System.out.println(" Error in validating Signature ");
			return false;
		}

		else {
			System.out.println(" Successfully validated Signature ");
			return true;
		}
	}

	// Cette méthode prend en paramètres un challenge et sa signature et vérifie
	// l'authenticité de cett dernière
	public static boolean verify(String challenge, byte[] signature,
			RSAPublicKey pubKey) {

		Signature myVerifySign;
		try {
			myVerifySign = Signature.getInstance("MD5withRSA");

			myVerifySign.initVerify(pubKey);
			myVerifySign.update(challenge.getBytes());

			boolean verifySign = myVerifySign.verify(signature);
			if (verifySign == false) {
				System.out.println(" Error in validating Signature ");
				return false;
			}

			else {
				System.out.println(" Successfully validated Signature ");
				return true;
			}

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;

	}

	public static byte[] aencRSA(byte[] plainText, RSAPublicKey pubKey)
			throws Exception {
		Cipher cipher;
		byte[] cipherText = null;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		cipherText = new byte[plainText.length];

		if (plainText.length > cipher.getBlockSize())

		{
			System.out.println("  plainTextSize > BigBlockSize :"
					+ plainText.length + ">" + cipher.getBlockSize());
			cipherText = cipherBigBlockSize(plainText, pubKey, cipher);

		} else
			cipherText = cipher.doFinal(plainText);
		System.out.println("RSA encrypted Text : " + new String(cipherText));

		// s = concat(cipherText);
		return cipherText;

	}

	private static byte[] cipherBigBlockSize(byte[] buffer,
			RSAPublicKey publickey, Cipher cipher) {

		byte[] raw = null;
		try {

			int blockSize = cipher.getBlockSize();
			int outputSize = cipher.getOutputSize(buffer.length);
			int leavedSize = buffer.length % blockSize;
			int blocksSize = leavedSize != 0 ? buffer.length / blockSize + 1
					: buffer.length / blockSize;
			raw = new byte[outputSize * blocksSize];
			int i = 0;
			while (buffer.length - i * blockSize > 0) {
				if (buffer.length - i * blockSize > blockSize)
					cipher.doFinal(buffer, i * blockSize, blockSize, raw, i
							* outputSize);
				else
					cipher.doFinal(buffer, i * blockSize, buffer.length - i
							* blockSize, raw, i * outputSize);
				i++;
			}

		} catch (ShortBufferException | IllegalBlockSizeException
				| BadPaddingException ex) {
			Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
					null, ex);
		}

		return raw;
	}

	public static byte[] adecRSA(byte[] cipherText, RSAPrivateKey privKey) throws Exception {
		 Security.addProvider(new
		 org.bouncycastle.jce.provider.BouncyCastleProvider());
		// ici on recupère un tableau de bytes décodé en base64

		byte[] plainText = null;

			int length = cipherText.length;
			plainText = new byte[length];

			// initialisation
			// Cipher cipher = Cipher.getInstance("RSA","BC");
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privKey);

			// déchiffrement
			// for( int i=0;i<length;i++){
			if (cipherText.length > cipher.getBlockSize())
				plainText = decipherBigBlockSize(cipherText, privKey);
			else
				plainText = cipher.doFinal(cipherText);
			// }
			System.out.println("\nEND decryption RSA");
			System.out.println("RSA decrypted Text : " + new String(plainText));

		return plainText;
	}

	private static byte[] decipherBigBlockSize(byte[] raw, RSAPrivateKey privKey) throws Exception {
		Security.addProvider(new
				 org.bouncycastle.jce.provider.BouncyCastleProvider());
		ByteArrayOutputStream bout = null;

		// Déchiffrement du fichier
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		int blockSize = cipher.getBlockSize();
		bout = new ByteArrayOutputStream(64);
		int j = 0;

		while (raw.length - j * blockSize > 0) {
			bout.write(cipher.doFinal(raw, j * blockSize, blockSize));
			j++;
		}

		return bout.toByteArray();

	}

	/*********************** concat ******************/
	// avant de faire apel à cette méthode les éléments du tableau args doivent
	// être convertis en byte [] chacun et insérer dans le tableau args
	// la valeur de retour doît être chiffrée et transformée en base64 avant
	// l'envoi
	public static String concat(byte[][] args) {

		String[] str = new String[args.length];
		for (int i = 0; i < args.length; i++)
			str[i] = new String(Base64.encode(args[i]));
		String s = str[0];
		for (int i = 1; i < str.length; i++)
			s += "#" + str[i];

		System.out.println("Message (concat) : --->" + s);
		return s;

	}

	/*********************** deconcat ***********************/

	// Une fois le mesage reçu, one le décode en base64 ,on le déchiffré on
	// obtient un log string en base64 avec des
	// "##, on fait ensuite appel à notre méthode "deconcat", evec avoir les
	// éléments chiffrés en clai

	public static byte[][] deconcat(String s) {
		String[] tab = s.split("#");
		byte[][] tab2 = new byte[tab.length][];
		// BASE64Decoder decoder = new BASE64Decoder();
		for (int i = 0; i < tab.length; i++) {

			tab2[i] = Base64.decode(tab[i]);
			System.out.println("Message " + i + " (deconcat) : --->"
					+ new String(tab2[i]));
		}

		return tab2;

	}

	/********************* generateDESSecretKey ****************/

	private static SecretKey generateAESSecretKey(int keySize) {
        SecretKey key=null;
    
    try {
            KeyGenerator keyGen1 = KeyGenerator.getInstance("AES");
            keyGen1.init(keySize);
            key = keyGen1.generateKey();
            System.out.println("\nGeneration de clé AES (128 bits)");
            return key;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE, null, ex);
        }
        return key;
    }

	/******************** initAESKey() *****************/

	public static SecretKey initAES128() {

		return generateAESSecretKey(128);
	}

	/************************* encAES128() ******************************/

	public static byte[] encAES128(byte[] plainText, SecretKey AESKey) {
		Cipher cipher;
		byte[] cipherText = null;
		try {
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, AESKey);

			cipherText = new byte[plainText.length];
			System.out.println("\nStart encryption AES128");

			cipherText = cipher.doFinal(plainText);
			System.out.println("encAES128 : ---> " + new String(cipherText));
			return cipherText;

		} catch (IllegalBlockSizeException | BadPaddingException
				| NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException ex) {
			Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
					null, ex);
		}
		return cipherText;

	}

	/**************************** decAES128() ********************************/

	public static byte[] decAES128(byte[] cipheredText, SecretKey AESKey) {
		Cipher cipher;
		byte[] plainText = null;
		try {
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, AESKey);

			plainText = new byte[cipheredText.length];
			System.out.println("\nStart decryption AES128");

			plainText = cipher.doFinal(cipheredText);
			System.out.println("decAES128 : ---> " + new String(plainText));
			return plainText;

		} catch (IllegalBlockSizeException | BadPaddingException
				| NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException ex) {
			Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
					null, ex);
		}
		return plainText;

	}

	/**************************** storePublicKeyEncoded ****************************/

	public static void storePublicKeyEncoded(String path, PublicKey publicKey) {
		FileOutputStream fos = null;
		try {
			// Store Public Key.
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
					publicKey.getEncoded());
			fos = new FileOutputStream(path);
			fos.write(x509EncodedKeySpec.getEncoded());
			fos.close();
		} catch (IOException ex) {
			Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
					null, ex);
		} finally {
			try {
				fos.close();
			} catch (IOException ex) {
				Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
						null, ex);
			}
		}

	}

	/*********************************** loadPublicKey *****************************************/

	public PublicKey loadPublicKey(String path, String algorithm) {

		FileInputStream fis = null;
		PublicKey publicKey = null;
		try {
			// Read Public Key.
			File filePublicKey = new File(path);
			fis = new FileInputStream(path);
			byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
			fis.read(encodedPublicKey);
			fis.close();
			// Generate KeyPair.
			KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
					encodedPublicKey);
			publicKey = keyFactory.generatePublic(publicKeySpec);
			return publicKey;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException
				| IOException ex) {
			Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
					null, ex);
		} finally {
			try {
				fis.close();
			} catch (IOException ex) {
				Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
						null, ex);
			}
		}
		return publicKey;
	}

	/*************************** storePrivateKeyEncoded () ***************************/

	public static void storePrivateKeyEncoded(String path, PrivateKey privateKey) {
		FileOutputStream fos = null;
		try {
			// Store Private Key.
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
					privateKey.getEncoded());
			fos = new FileOutputStream(path);
			fos.write(pkcs8EncodedKeySpec.getEncoded());
			fos.close();
		} catch (IOException ex) {
			Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
					null, ex);
		} finally {
			try {
				fos.close();
			} catch (IOException ex) {
				Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
						null, ex);
			}
		}
	}

	/************************ loadPrivateKey() ************************/

	public static PrivateKey loadPrivateKey(String path, String algorithm) {
		FileInputStream fis = null;
		PrivateKey privateKey = null;
		try {
			// Read Private Key.
			File filePrivateKey = new File(path);
			fis = new FileInputStream(path);
			byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
			fis.read(encodedPrivateKey);
			// fis.close();
			// Generate KeyPair.
			KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
					encodedPrivateKey);
			privateKey = keyFactory.generatePrivate(privateKeySpec);
			return privateKey;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException
				| IOException ex) {
			Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
					null, ex);
		} finally {
			try {
				fis.close();
			} catch (IOException ex) {
				Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
						null, ex);
			}
		}

		return privateKey;
	}

	/***************************** keyStore ************************/

	/***
	 * il y a un problème avac cette méthode
	 * 
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 ***/
	public void storePrivKeyKeyStore(PrivateKey privKey)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, IOException {

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null, null);

		X509Certificate[] certChain = new X509Certificate[1];

		ks.setKeyEntry("privKeyBanque", privKey, "password".toCharArray(),
				certChain);

		ks.store(new FileOutputStream("keyStore.ks"), "password".toCharArray());
		System.out.println("Creation de KeyStore");

	}

	public static String loadPublicKey(String path) {
		FileInputStream fis = null;

		// Read Public Key.
		File filePublicKey = new File(path);
		try {
			fis = new FileInputStream(path);

			byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];

			fis.read(encodedPublicKey);
			fis.close();
			System.out
					.println("loadPublikey : PubKey Origini (Encoded) : ---->"
							+ new String(encodedPublicKey));
			String key = new String(Base64.encode(encodedPublicKey));
			System.out.println("loadPublikey : PubKey (Base 64) : ---->" + key);
			return key;

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static PublicKey getPublicKeyBase64(String keyBase64) {

		byte[] keyEncoded = Base64.decode(keyBase64.getBytes());

		return getPublicKey1(keyEncoded);

	}

	/*************************** getPublicKey ******************/
	public static PublicKey getPublicKey1(byte[] key) {
		// return getRSAPubKeyEncoded(key);
		return getPublicKeyEncoded(key);
	}

	public static PublicKey getPublicKeyEncoded(byte[] publicKeyData) {

		PublicKey pk = null;
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
					publicKeyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
			pk = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

			return pk;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException
				| NoSuchProviderException ex) {
			Logger.getLogger(CryptoUtils.class.getName()).log(Level.SEVERE,
					null, ex);
		}
		return pk;
	}

	// ///////////////////////////////////////////////

	// génération de paire de clés RSA

	public static void generateKeyPairs(String pubKeyPath, String privKeyPath) {

		KeyPairGenerator keyGen;
		try {

			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keyPair = keyGen.genKeyPair();

			// pubKey generation and storing
			RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
			storePublicKeyEncoded(pubKeyPath, pubKey);

			// privKey generation and storing

			RSAPrivateKey privKey = (RSAPrivateKey) keyPair.getPrivate();
			storePrivateKeyEncoded(privKeyPath, privKey);
			// storePrivKeyKeyStore(privKey);

			System.out.println("pubKey (pubKeyBanque.key): -> "
					+ new String(pubKey.getEncoded()));
			System.out.println("privKey (privKeyBanque.key): -> "
					+ new String(privKey.getEncoded()));

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	// Cette méthode permet d'initialiser nos deux clés de type RSA

	// public static void main (String [] args ) {
	//
	// CryptoUtils util = new CryptoUtils() ;
	// util.initRSAKeys();
	// pubKey = (RSAPublicKey) util.loadPublicKey("pubKeyBanque.key", "RSA");
	// privKey = (RSAPrivateKey) util.loadPrivateKey("privKeyBanque.key",
	// "RSA");
	// secretKey = util.initAES128() ;
	//
	//
	// receiveSessionKey(sendSessionKey (secretKey.getEncoded(),pubKey));
	//
	//
	// receiveLoginPassword(sendLoginPassword("login","password".getBytes(),secretKey),secretKey);

	// TODO récup fonction !!
	// String message = "ceci est un test" ;
	// util.digest(message);
	// byte [] signature = util.sign2(message, util.privKey);
	// util.verify(message, signature, util.pubKey);
	//
	//
	//
	//
	// byte[] cipherText1 ,cipherText2,cipherText3;
	// try {
	//
	//
	//
	// // chiffrement
	// cipherText1 = "test".getBytes();
	// cipherText2 ="Ali".getBytes();
	// cipherText3 = "Abdelleh".getBytes() ;
	//
	// byte [] [] tab = {cipherText1, cipherText2, cipherText3} ;
	//
	//
	// String messg = concat(tab) ;
	//
	// byte [] tab3 = util.aencRSA(messg.getBytes(), pubKey);
	//
	// // déchiffrement
	//
	// byte [] tab4 = util.adecRSA(tab3, privKey);
	// byte [] [] tab5 = deconcat(new String(tab4)) ;
	//
	//
	// //chiffrement AES128
	//
	// byte tab6 [] = util.encAES128("message pour test AES128".getBytes(),
	// secretKey);
	// util.decAES128(tab6, secretKey);
	//
	//
	//
	//
	//
	//
	//
	// } catch (NoSuchProviderException e) {
	//
	// e.printStackTrace();
	// }
	//
	//
	//
	//
	//
	//
	// }

}
