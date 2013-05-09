package engine;

import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServlet;
import javax.servlet.ServletContext;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Servlet implementation class Main
 */
@Path("/Main")
public class Main extends HttpServlet {
	
	private static final long serialVersionUID = 1L;
	private Engine engine = new Engine();
	

    public Main() {
        super();
    }
    
    @Context
	ServletContext context;
	
	@GET
	@Produces( MediaType.TEXT_PLAIN )
	public String sayPlainTextHello(@DefaultValue("error") @QueryParam("cipher") String cipher,
									@DefaultValue("error") @QueryParam("id") String id){
		
		// Premier échange : pour générer la clé de session
		if(!cipher.equals("error") && id.equals("1")) {

			byte[][] temp;
			try {
				temp = engine.receiveChallenge(cipher);
			} catch (Exception e) {
				return "Erreur : " + e.getMessage() + "\nAutre code : "+ e.toString();
			}
			
			String nomBanque = new String(temp[1]);
			String hash = new String(temp[2]);
			System.out.println("Valeurs récup : \nNom banque : "+nomBanque+" - Hash : "+hash);
			
			RSAPublicKey pubKey = engine.verifBanque(nomBanque, hash);
			if(pubKey != null) {
				SecretKey sessionKey = engine.sessionKeyGenerator();
				if(sessionKey == null) return "Erreur de gen sessionKey";
				
				// Ajout de la clé de session dans properties pour persistence
				System.getProperties().put("key", sessionKey);
				return engine.sendSessionKey(sessionKey, pubKey);
			}
			return "null";
		} 
		
		// Second échange : données d'authentification du client
		else if(!cipher.equals("error") && id.equals("2")) {
			
			// Récupération de la clé de session enregistrée dans les properties
			SecretKey sessionKey = (SecretKey)System.getProperties().remove("key");
			byte[][] temp = engine.receiveLoginPassword(cipher, sessionKey);
			String login = new String(temp[0]);
			String mdp = new String(temp[1]);
//			String hash = new String(temp[2]);
			
			try {
				// Vérification des credentials utilisateur
				if(engine.verifUser(login, mdp, "")) return engine.sendOK(sessionKey);
				else return engine.sendFalse(sessionKey);
			} catch (Exception e) {
				return "Erreur : "+e.getMessage();
			}
		} 
		
		// Dernier cas
		else {
			return "Pas d'arguments / erreurs dans les arguments passés";
		}
	}
}
