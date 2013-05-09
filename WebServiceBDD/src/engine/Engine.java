package engine;

import java.nio.ByteBuffer;
import java.sql.*;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;

import org.bouncycastle.util.encoders.Base64;

public class Engine {

	private Statement state = null;

	public Engine() {
		String host = System.getenv("OPENSHIFT_MYSQL_DB_HOST");
		String port = System.getenv("OPENSHIFT_MYSQL_DB_PORT");
		String url = String.format("jdbc:mysql://%s:%s/wsbdd", host, port);

		try {
			Class.forName("com.mysql.jdbc.Driver");
			Connection Connexion = DriverManager.getConnection(url,
					"adminRf3g7If", "RPGjUx1GUsiX");
			state = Connexion.createStatement();
		} catch (SQLException | ClassNotFoundException e1) {
		}
	}

	public RSAPublicKey verifBanque(String nom_banque, String hash) {
		String id_banque = null;
		PublicKey pubKey = null;

		try {
			ResultSet resultat = state.executeQuery("SELECT * FROM `banques` WHERE nom='" + nom_banque + "'");
			while (resultat.next()) {
				pubKey = Engine.getPublicKeyBase64(resultat.getString("pubKey"));
				id_banque = resultat.getString("id");
			}
		} catch (Exception e) {
			System.out.println("Erreur dans verify banque : "+e.getMessage() +"\n"+e.getLocalizedMessage());
			return null;
		}
		
		// Vérification du ID et de son hash
//		if (CryptoUtils.verify(id_banque, hash, pubKey))
//			return cle_pub;
		return (RSAPublicKey)pubKey;
	}

	public boolean verifUser(String login, String mdp, String hash) throws Exception {
		RSAPublicKey pubKey = null;

		// Premier test de login / mdp
		String query = "SELECT * FROM `credentials` WHERE login='" + login+ "' and mdp='" + mdp + "'";

		ResultSet resultat = state.executeQuery(query);
		if(resultat.next()) {
			pubKey = (RSAPublicKey) Engine.getPublicKeyBase64(resultat.getString("pubKey"));
			return true;
		}
			
		// Vérification du ID et de son hash
//		if (CryptoUtils.verify(mdp, hash, pubKey)) return true;
		return false;
	}

	// Génère une clé de session
	public SecretKey sessionKeyGenerator() {
		return CryptoUtils.initAES128();
	}
	
	
	// ******************************************************************************
	//
	//						FONCTIONS D'ECHANGES DE DONNEES
	//
	// ******************************************************************************
	
	public byte[][] receiveChallenge (String chaine_recu) throws Exception {
		
		// Les + sont transformés en espace !! Il faut les remettre dans la chaine envoyée
		byte []  chaine = Base64.decode(chaine_recu.replaceAll(" ", "+"));

		RSAPrivateKey privKey = null;
		ResultSet resultat = state.executeQuery("SELECT * FROM `keys` WHERE nom='private'");
		while (resultat.next()) {
			privKey = (RSAPrivateKey) Engine.getPrivateKeyBase64(resultat.getString("key"));
		}
		
		byte[] dec = CryptoUtils.adecRSA(chaine, privKey);
		if(dec == null) return null;
		byte deconc [][] = CryptoUtils.deconcat(new String(dec));
		
		return deconc;
	}
	
	public String sendSessionKey (SecretKey sessionKey, RSAPublicKey pubKey){
		
		long time_l =  System.currentTimeMillis();
		byte [] time = ByteBuffer.allocate(8).putLong(time_l).array();
		
		
		byte [][] tab = new byte [2][];
		tab [0] = time;
		tab [1] = sessionKey.getEncoded();
		
		String chaine_concat = CryptoUtils.concat(tab);
		
		try {
			byte[] enc = CryptoUtils.aencRSA(chaine_concat.getBytes(), pubKey);
			
			 System.out.println("sendSessionKey : --> "+new String(enc));
			 System.out.println("sendSessionKey (time) : --> "+new String(time));
			return new String(Base64.encode(enc));
		} catch (Exception e) {
			return e.getMessage();
		}
	}
	
	public byte[][] receiveLoginPassword (String chaine_recu,SecretKey Ksession){

		byte [] chaine = Base64.decode(chaine_recu.replaceAll(" ", "+"));
		
		byte[] dec = CryptoUtils.decAES128(chaine, Ksession);
		byte deconc [][] = CryptoUtils.deconcat(new String(dec));
		 System.out.println("receiveLogin: -->"+new String(deconc[0]));
		 System.out.println("receivePassword: --> "+deconc[1]);
		return deconc;
	}
	
	public String sendOK(SecretKey Ksession){
		
		String accept = new String("ACCEPT");
		byte [] reponse = accept.getBytes();
		
		
		try {
			byte[] enc = CryptoUtils.encAES128(reponse, Ksession);
			return new String(Base64.encode(enc));
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;	
	}

	public String sendFalse(SecretKey Ksession){
		
		String accept = new String("REFUSE");
		byte [] reponse = accept.getBytes();
		
		try {
			byte[] enc = CryptoUtils.encAES128(reponse, Ksession);
			return new String(Base64.encode(enc));
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
	
	
	// ******************************************************************************
	//
	//						FONCTIONS DE CHIFFREMENT ET CLES
	//
	// ******************************************************************************

	public static PublicKey getPublicKeyBase64(String keyBase64) {

		byte[] keyEncoded = Base64.decode(keyBase64.getBytes());
		return getPublicKeyEncoded(keyEncoded);
	}

	private static PublicKey getPublicKeyEncoded(byte[] publicKeyData) {

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
			//Logger.getLogger(API.class.getName()).log(Level.SEVERE, null, ex);
		}
		return pk;
	}
	
	public static PrivateKey getPrivateKeyBase64(String keyBase64) throws Exception {

		byte[] keyEncoded = Base64.decode(keyBase64.getBytes());
		return getPrivateKeyEncoded(keyEncoded);
	}
	
	private static PrivateKey getPrivateKeyEncoded(byte[] encodedPrivateKey) throws Exception {
		PrivateKey privateKey = null;

		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		privateKey = keyFactory.generatePrivate(privateKeySpec);
		return privateKey;
	}
}
