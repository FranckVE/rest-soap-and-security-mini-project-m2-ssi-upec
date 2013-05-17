package webservice;

import java.nio.ByteBuffer;
import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.LinkedList;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletContext;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cryptos.CryptoUtils;

@Path("/transaction")
public class Transaction {

	@Context ServletContext context;

    
	@GET
	@Produces( MediaType.TEXT_HTML )
	public String sayPlainTextHello(@DefaultValue("seeAccounts") @QueryParam("token") String token,
									@DefaultValue("test") @QueryParam("login") String login){
		
		Security.addProvider(new BouncyCastleProvider());
		
		// Ouverture vers BDD de la banque
		String host = System.getenv("OPENSHIFT_MYSQL_DB_HOST");
		String port = System.getenv("OPENSHIFT_MYSQL_DB_PORT");
		String url = String.format("jdbc:mysql://%s:%s/wsbanque", host, port);
		Statement state = null;
		try {
			Class.forName("com.mysql.jdbc.Driver");
			Connection Connexion = DriverManager.getConnection(url, "admin3JrZAdc", "dUrDdRkl6DAV");
			state = Connexion.createStatement();
		} catch (SQLException | ClassNotFoundException e1) {
			return "Erreur : " + e1.getMessage();
		}
		
		//-------------------------------------------------------------------------------------------
		
		// Récupération de la clé de session
//		byte[] sessionKey_b = (byte[]) System.getProperties().get(login+"-sessionKey");
//		if(sessionKey_b == null) return "Erreur : pas de clé de session";
//		SecretKey sessionKey = new SecretKeySpec(sessionKey_b, 0,sessionKey_b.length, "AES");
		SecretKey sessionKey = (SecretKey) System.getProperties().get(login+"-sessionKey");
		if(sessionKey == null) return "Erreur : pas de clé de session";
		
		
		// Déchiffrement token
		String req = null;
		try {
			req = CryptoUtils.receiveTextCipherSymetric(token, sessionKey);
		} catch (Exception e) {
			return "Erreur : déchiffrement du token";
		}
		
		
		
		// Requete sur la BDD des comptes
		// Transfert d'argent
		if(req == null) return "Erreur : Req = null";
		if(!req.contains("seeAccount")) {
			try {

				String source = req.substring(0, req.indexOf("@"));
				String dest = req.substring(req.indexOf("@"+1), req.indexOf("="));
				String value = req.substring(req.indexOf("="+1), req.length());
				
				// Requete sur la BDD des comptes (étape 1)
				String requete = "UPDATE comptes SET argent=argent-"+value+" WHERE num_compte='"+source+"'";
				state.executeQuery(requete);
				
				// Requete sur la BDD des comptes (étape 2)
				requete = "UPDATE comptes SET argent=argent+"+value+" WHERE num_compte='"+dest+"'";
				state.executeQuery(requete);
				
			} catch (Exception e) {
				return "Erreur : requete mise à jour comptes\nType d'erreur : "+e.getMessage();
			}
		} 
		
		// Visualisation des comptes (dans tous les cas)
		try {
			String requete = "SELECT num_compte, type_compte, argent FROM comptes WHERE login='"+login+"'";
			ResultSet res = state.executeQuery(requete);
			
			LinkedList<String> nums = new LinkedList<String>();
			LinkedList<String> types = new LinkedList<String>();
			LinkedList<Float> vals = new LinkedList<Float>();
			while(res.next()) {
				nums.addLast(res.getString("num_compte"));
				types.addLast(res.getString("type_compte"));
				vals.addLast(res.getFloat("argent"));
			}
			
			
			
			byte[][] accounts = new byte[(nums.size())*3][];
			int j = 0;
			for(int i = 0; i < accounts.length; i=i+3) {
				accounts[i] = nums.get(j).getBytes();
				accounts[i+1] = types.get(j).getBytes();
				accounts[i+2] = (""+vals.get(j)).getBytes();
				j++;
			}
			
			String chaineAccounts = CryptoUtils.concat(accounts);
			return CryptoUtils.sendTextCipherSymetric(chaineAccounts, sessionKey);
			
		} catch (Exception e) {
			return "Erreur : requete d'affichage des comptes\nCode d'erreur : "+e.getMessage();
		}
	}
}
