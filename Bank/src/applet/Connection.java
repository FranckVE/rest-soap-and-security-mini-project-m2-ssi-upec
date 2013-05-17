package applet;

import java.applet.*;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.UrlBase64;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;

import cryptos.CryptoUtils;

public class Connection extends Applet {
	
	public static final String KEY_PATH = "C:\\Temp\\privKey.key";
	public static final String PUBKEY_BANQUE_BASE64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChxF0MhGErpsvBOPtBSR5yikucSsITgmaQ+RlcRpoU70eE9YSf+O6pb66TYW9yfF/XLkKooR0KUeV1C5TeIQU7ViDGmaoRzIx+4Cglc/k0eNtTac1KI6YT77pOSSoACUhNGH5WIT9vyapqkVE3sifubm4OGj/nTCkX6U/lEL8UhQIDAQAB";
	
	private JPasswordField zPassword = new JPasswordField();
	private JTextField zLogin = new JTextField();
	private JTextField zKeyBase64 = new JTextField();
	private JButton valid = new JButton(" Ok ");
	
	public void init() {
		zLogin.setPreferredSize(new Dimension(140, 30));
		zPassword.setPreferredSize(new Dimension(100, 30));
		zKeyBase64.setPreferredSize(new Dimension(160, 30));
		valid.addActionListener(new ActionBouton());
		
		add(new JLabel("Login : "));
		add(zLogin);
		add(new JLabel("Mot de passe : "));
		add(zPassword);
		add(new JLabel("Key : "));
		add(zKeyBase64);
		add(valid);
	}
	
	public void maj(boolean authenticating) {
		removeAll();
		if(authenticating) {
			add(new JLabel("Authentification ..."));
		} else {
			JLabel error = new JLabel("Error : Please retry ...");
			error.setForeground(Color.RED);
			error.setPreferredSize(new Dimension(200,25));
			add(error);
			add(new JLabel("Login : "));
			add(zLogin);
			add(new JLabel("Password : "));
			add(zPassword);
			add(valid);
		}
		repaint();
		validate();
	}
	
	
	private class ActionBouton implements ActionListener {
		
		@Override
		public void actionPerformed(ActionEvent arg0) {
			
			try {
				String login = zLogin.getText();
				String mdp = new String(zPassword.getPassword());
				String privKeyBase64 = zKeyBase64.getText();
				
				if(login == null || mdp == null || login.isEmpty()) maj(false);
				else {
					// Mise à jour graphics de l'applet
					maj(true);
					
					Client c = Client.create();
					
					// Récupération des clés
					RSAPrivateKey privKey = (RSAPrivateKey) CryptoUtils.getPrivateKeyBase64(privKeyBase64);
					RSAPublicKey pubKeyBank = (RSAPublicKey) CryptoUtils.getPublicKeyBase64(PUBKEY_BANQUE_BASE64);
					
					// Hash du mot de passe et signature du hash
					String mdpSHA1 = CryptoUtils.digestSHA1(mdp);
					byte[] signature = CryptoUtils.signSHA1(mdpSHA1, privKey);
					
					// Génération clé de session
					SecretKey sessionKey = CryptoUtils.initAES128();
					System.getProperties().put("sessionKey", sessionKey);
					
					// Sauvegarde login
					System.getProperties().put("login", login);
					
					// Création du token
					byte[][] tabToken = {login.getBytes(), sessionKey.getEncoded(), mdpSHA1.getBytes(), signature };
					String temp = CryptoUtils.concat(tabToken);
					byte [] result = CryptoUtils.aencRSA(temp.getBytes(), pubKeyBank);
					String token = new String(Base64.encode(result));
					
					// Envoi des informations de connexion
//					WebResource resource = c.resource("http://localhost:8080/Bank/rest/hello?token="+token);
					WebResource resource = c.resource("http://wsbanque-projetcdai.rhcloud.com/Bank/rest/hello?token="+token);
					String response = resource.get(String.class);
					System.out.println("Response : "+response);
					if(!response.contains("Erreur :")) {
						String resp = CryptoUtils.receiveTextCipherSymetric(response, sessionKey);
						
						if(resp.contains("ACCEPT"))
							getAppletContext().showDocument(new URL(getCodeBase()+"accueil.html"),"_top");
						else
							getAppletContext().showDocument(new URL(getCodeBase()+"index.html"),"_top");
					} else {
						JOptionPane.showMessageDialog(null, "Erreur sur le serveur distant ! Recommencez plus tard ...\n"+response, "Erreur", JOptionPane.ERROR_MESSAGE);
					}
				}
			} catch (Exception e) {
				JOptionPane.showMessageDialog(null, e.getMessage(), "Erreur", JOptionPane.ERROR_MESSAGE);
				e.printStackTrace();
			}
		}
	}
	
	private String panelKeyBase64() {
		return JOptionPane.showInputDialog(null, "Please insert here the base64 code of your private key.\nYour private key will not be intercepted or decoded.\nIt stays on your local host.", "Private Key encoded BASE64", JOptionPane.QUESTION_MESSAGE);
	}
}
