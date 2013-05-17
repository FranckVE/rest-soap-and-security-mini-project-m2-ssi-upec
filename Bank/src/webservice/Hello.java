package webservice;

import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

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

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;

import cryptos.CryptoUtils;


/**
 * This is Lars' REST server application described at http://www.vogella.de/articles/REST/article.html
 * 3.2. Java class
 *
 * The class registers itself using @GET. using the @Produces, it defines that it delivers two MIME types,
 * text and HTML. The browser always requests the HTML MIME type. Also shown is how to get a hold of
 * the HTTP ServletContext you'd have if you weren't using Jersey and all of this nice annotation.
 *
 */
// Sets the path to base URL + /hello
@Path( "/hello" )
public class Hello
{

    @Context ServletContext context;

    
	@GET
	@Produces( MediaType.TEXT_HTML )
	public String sayPlainTextHello(@DefaultValue("test") @QueryParam("token") String token){

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
		
		Client c = Client.create();
		String name_s = "wsbanque";
		int id_i = 1;
		
		// Récupération des clés
		RSAPublicKey pubKeyBDD = null;
		RSAPrivateKey privKey = null;
		try {
			ResultSet resultat = state.executeQuery("SELECT * FROM `keys` WHERE nom='pubkeybdd'");
			while (resultat.next()) {
				pubKeyBDD = (RSAPublicKey) CryptoUtils.getPublicKeyBase64(resultat.getString("key"));
			}
			
			resultat = state.executeQuery("SELECT * FROM `keys` WHERE nom='private'");
			while (resultat.next()) {
				privKey = (RSAPrivateKey) CryptoUtils.getPrivateKeyBase64(resultat.getString("key"));
			}
		} catch (Exception e) {
			return "Erreur : " + e.getMessage();
		}
		
		// Déchiffrement du token envoyé par l'applet d'authentification
		byte[][] tab = CryptoUtils.receiveAndDechiperAsymetric(privKey, token.replaceAll(" ", "+"));
		String login = new String(tab[0]);
		byte[] bKsession_client = tab[1];
		byte[] passwordSHA1 = tab[2];
		byte[] signSHA1 = tab[3];
		
		// Sauvegarde de la clé de session dans le système
		SecretKey Ksession_client = new SecretKeySpec(bKsession_client, 0,bKsession_client.length, "AES");
		System.getProperties().put(login+"-sessionKey", Ksession_client);
		

		// ##################### 		Premier échange 		###################################
		String challenge = CryptoUtils.sendChallenge(name_s,id_i,pubKeyBDD, privKey);
		WebResource resource = c.resource("http://wsbdd-projetcdai.rhcloud.com/WebService/rest/Main?cipher="+challenge+"&id=1");
		System.out.println("Challenge = "+challenge);

		
		// ##################### 	Réception premier échange 	###################################
		String response = resource.get(String.class);
		System.out.println("--> "+response+" <--");
		if(response.equalsIgnoreCase("null")) return "Erreur dans l'inter-communication des web services !\nCause : return null";
		
		if(response.contains("Erreur :")) return response;
		tab = CryptoUtils.receiveAndDechiperAsymetric(privKey, response.replaceAll(" ", "+"));
		byte [] Ksession_b = tab[1]; // tab[0] contient l'horodatage

		SecretKey Ksession = new SecretKeySpec(Ksession_b, 0,Ksession_b.length, "AES");
		System.out.println(Ksession.getFormat());
		
		
		// ##################### 	    Deuxième échange 		###################################
		String logpass = CryptoUtils.sendLoginPassword(login, passwordSHA1, signSHA1, Ksession);
		resource = c.resource("http://wsbdd-projetcdai.rhcloud.com/WebService/rest/Main?cipher="+logpass+"&id=2");

		
		// ##################### 	Réception deuxième échange 	###################################
		response = resource.get(String.class);
		if(response.contains("Erreur :")) return response;
		
		try {
			String resp = CryptoUtils.receiveReponse(response, Ksession);
			return CryptoUtils.sendTextCipherSymetric(resp, Ksession_client);
		} catch (Exception e) {
			return "Error decryption : "+e.getMessage();
		}
	}

	// This method is called if request is TEXT_PLAIN
	/*
	@GET
	@Produces( MediaType.TEXT_HTML )
	public String sayPlainTextHello(   @DefaultValue("test") @QueryParam("login") String  log,
		                               @DefaultValue("test") @QueryParam("password") String pass0	){

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
		
		Client c = Client.create();
		
//		WebResource resource = c.resource("http://wsbdd-projetcdai.rhcloud.com/WebService/rest/echotest?login="+log+"&password="+pass0);
//		String response = resource.get(String.class);
//		return response;
//		
		//envoie premiére echange
		
		String name_s = "wsbanque";
		int id_i = 1;
		
//		System.out.println("ok"+1);
//		RSAPublicKey pubKey = (RSAPublicKey) CryptoUtils.loadPublicKey("pubKeyBDD.key", "RSA");
//		System.out.println("ok");
		
		// Récupération des clés
		RSAPublicKey pubKeyBDD = null;
		RSAPrivateKey privKey = null;
		try {
			ResultSet resultat = state.executeQuery("SELECT * FROM `keys` WHERE nom='pubkeybdd'");
			while (resultat.next()) {
				pubKeyBDD = (RSAPublicKey) CryptoUtils.getPublicKeyBase64(resultat.getString("key"));
			}
			
			resultat = state.executeQuery("SELECT * FROM `keys` WHERE nom='private'");
			while (resultat.next()) {
				privKey = (RSAPrivateKey) CryptoUtils.getPrivateKeyBase64(resultat.getString("key"));
			}
		} catch (Exception e) {
			return "Erreur : " + e.getMessage();
		}
		
//		try {
//			pubKeyBDD = (RSAPublicKey) CryptoUtils.getPublicKeyBase64("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzrKSpujgdeu8o9OIdcfblairF2sZ1yLooqfRMyP2z4VSvqtO0L7U1LXgJdzmQa0ln8tCM3/S3ET7UrenlrKawaHnHsBCujif6fcg0I1KK8HY9kyDd+pef+gw+QH7jBzu+zsU/dxHivyruggdXi1idNxVD4ZtwHzblVGO71nfWAQIDAQAB");
//			privKey = (RSAPrivateKey) CryptoUtils.getPrivateKeyBase64("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKHEXQyEYSumy8E4+0FJHnKKS5xKwhOCZpD5GVxGmhTvR4T1hJ/47qlvrpNhb3J8X9cuQqihHQpR5XULlN4hBTtWIMaZqhHMjH7gKCVz+TR421NpzUojphPvuk5JKgAJSE0YflYhP2/JqmqRUTeyJ+5ubg4aP+dMKRfpT+UQvxSFAgMBAAECgYEAja9IdGMqHKqNweIfpvHc+iOI0A5mZ+IJ5aZYAQtRf06IjLrh+59zofHQrQNlMpge9YBuH/ZlUhmi6N5I+Dlhs08qr+GBlCIBXq9ng03wa+Mv1Hn1W645nx3ojFUuMa6bTDwdXTJsifi/0LDmQrtebLMhGdz9bh70b/HIG36812ECQQDS5LgB1xEnpUviJ4giWmH86Ql77oXyqVVcXk5QakbzKvNJU66E0G/e4/KRBy0lw5NxwJI15/8VJOwVP6yt4kg9AkEAxF3F9YPHgH2ayZAEltM9WA8sG2o5Hf7yMjCJnOQ1rFqSaW9JOB+vE5ac0YhHtBxa8cUPC12kV9jkq6Jy3Cj56QJAQ1nsMho/TkwJ+gXqAh6fYKgD8WJxwNe3fTJZDHGEizBSVj61Y5E1yRc/ZnXGQ2M8eX2otDKNUnFiPD8DpNy5eQJAUmTyimkoDe8mQssuUccDJ27+V+aDXuW55HtfUrijGNXMN3ddprIMuVBqLrVbOOTo+Cdyf5dkPQQiNy5ruZtr+QJAQAAzQB+9dqiUEKuJHpNSnji0RiFrTJQjNSxsP80GcutjJxMrlPBN4f9zZhI+RgksVNJJUiEUA9oC80DzIUL5SA==");
//		} catch (Exception e) {
//			return "Erreur gen clés";
//		}
		
		String challenge = CryptoUtils.sendChallenge(name_s,id_i,pubKeyBDD, privKey);
		
		WebResource resource = c.resource("http://wsbdd-projetcdai.rhcloud.com/WebService/rest/Main?cipher="+challenge+"&id=1");
		System.out.println("Challenge = "+challenge);
		
		// pour tester
//		String response = resource.get(String.class);
//		return response;
		//fin test
		
		//reception premier echange
		String response = resource.get(String.class);
		System.out.println("--> "+response+" <--");
		if(response.equalsIgnoreCase("null")) return "Erreur dans l'inter-communication des web services !\nCause : return null";
		
		byte [][] tab = CryptoUtils.receiveAndDechiperAsymetric(privKey, response.replaceAll(" ", "+"));
		byte [] Ksession_b = tab[1];
		
		
		//recuper la clé de session a partir du tab []
		SecretKey Ksession = new SecretKeySpec(Ksession_b, 0,Ksession_b.length, "AES"); // A tester
		System.out.println(Ksession.getFormat());
		
		
    	//envoi du Login et md5(password)
		byte [] passmd = pass0.getBytes(); //a faire
		String logpass = CryptoUtils.sendLoginPassword(log, passmd, Ksession);
		resource = c.resource("http://wsbdd-projetcdai.rhcloud.com/WebService/rest/Main?cipher="+logpass+"&id=2");
		
		// pour tester
//		response = resource.get(String.class);
//		return response;
		//fin test
		
//		return "Login : "+log + " et "+new String(passmd)+"\nCle de session "+new String(Ksession.getEncoded());
		
		//reception deuxiéme echange
		response = resource.get(String.class);
		if(response.contains("Erreur :")) return response;
		
		String rep = "";
		try {
//			return "Message reçu : --> " +response +" <-- </br>Message décodé : " + new String(Base64.decode(response));
			rep = CryptoUtils.receiveReponse(response, Ksession);
		} catch (Exception e) {
			return "Error decryption : "+e.getMessage();
		}
		
		//pour tester
		System.out.println(rep);
		return ""+rep;
	    //fin test
	} */
}
