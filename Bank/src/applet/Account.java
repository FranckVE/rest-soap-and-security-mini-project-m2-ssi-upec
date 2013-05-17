package applet;

import java.applet.*;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.crypto.SecretKey;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;

import cryptos.CryptoUtils;

public class Account extends Applet{

	private SecretKey sessionKey = null;
	private String login = null;
	
	private JTextField tfSender = new JTextField();
	private JTextField tfReceiver = new JTextField();
	private JTextField tfCash = new JTextField();
	
	public void init() {

		// Récupération clé de session + login
		sessionKey = (SecretKey) System.getProperties().remove("sessionKey");
		login = (String) System.getProperties().remove("login");
		if(sessionKey == null) JOptionPane.showMessageDialog(null, "Pas de clé de session", "Erreur", JOptionPane.ERROR_MESSAGE);
		if(login == null) JOptionPane.showMessageDialog(null, "Pas de login", "Erreur", JOptionPane.ERROR_MESSAGE);
		System.out.println("Login : "+login);
		
		// Chiffrement des paramètres
		String token = CryptoUtils.sendTextCipherSymetric("seeAccount", sessionKey);
		
		// Demande d'affichage des comptes
		Client c = new Client();
		WebResource resource = c.resource("http://wsbanque-projetcdai.rhcloud.com/Bank/rest/transaction?token="+token+"&login="+login);
		String response = resource.get(String.class);
		
		// Création du tableau de synthèse
		if(!response.contains("Erreur :")) {
			try {
				// Fonction de création du tableau des comptes
				String[][] data = reconstructeur(response);
				
				// Ajout des composants graphiques
				ajoutComposants(data);
				
			} catch (Exception e) {
				JOptionPane.showMessageDialog(null, e.getMessage(), "Erreur", JOptionPane.ERROR_MESSAGE);
				e.printStackTrace();
			}
		} else {
			JOptionPane.showMessageDialog(null, response, "Erreur serveur distant", JOptionPane.ERROR_MESSAGE);
		}
	}
	
	private String[][] reconstructeur(String response) throws Exception {
		
		// Déchiffrement du payload
		String temp = CryptoUtils.receiveTextCipherSymetric(response, sessionKey);
		byte[][] tab = CryptoUtils.deconcat(temp);
		
		// Construction tableau
		String[][] data = new String[tab.length/3][3];
		
		int j = 0;
		for(int i = 0; i < tab.length; i=i+3) {
			data[j][0] = new String(tab[i]);
			data[j][1] = new String(tab[i+1]);
			data[j][2] = new String(tab[i+2]);
			j++;
		}
		
		return data;
	}
	
	private void ajoutComposants(String[][] data) {
		removeAll();

		String titles[] = {"ID Number", "Account type", "Cash"};
		JTable comptes = new JTable(data, titles);
		add(new JScrollPane(comptes), BorderLayout.CENTER);
		
//		JLabel label = new JLabel("Transfer of cash between accounts :");
//		label.setPreferredSize(new Dimension(350,35));
//		add(label, BorderLayout.CENTER);
//		
//		label = new JLabel("Account sender (id number) :");
//		add(label, BorderLayout.CENTER);
//		
//		tfSender.setPreferredSize(new Dimension(200,25));
//		add(tfSender, BorderLayout.CENTER);
//		
//		label = new JLabel("Account receiver (id number) :");
//		add(label, BorderLayout.CENTER);
//		
//		tfReceiver.setPreferredSize(new Dimension(200,25));
//		add(tfReceiver, BorderLayout.CENTER);
//		
//		label = new JLabel("Cash to transfer :");
//		add(label, BorderLayout.CENTER);
//		
//		tfCash.setPreferredSize(new Dimension(90,25));
//		add(tfCash, BorderLayout.CENTER);
//		
//		JButton bouton = new JButton("Validate");
//		bouton.addActionListener(new ActionBouton());
//		add(bouton, BorderLayout.CENTER);
		
		repaint();
		validate();
	}
	
	private class ActionBouton implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent arg0) {
			
			// Chiffrement de la demande
			String req = tfSender.getText()+"@"+tfReceiver.getText()+"="+tfCash.getText();
			String token = CryptoUtils.sendTextCipherSymetric(req, sessionKey);
			
			// Demande d'action
			Client c = new Client();
			WebResource resource = c.resource("http://wsbanque-projetcdai.rhcloud.com/Bank/rest/transaction?token="+token+"&login="+login);
			String response = resource.get(String.class);
			
			// Création du tableau de synthèse
			if(!response.contains("Erreur :")) {
				try {
					// Fonction de création du tableau des comptes
					String[][] data = reconstructeur(response);
					
					// Ajout des composants graphiques
					ajoutComposants(data);
					
				} catch (Exception e) {
					JOptionPane.showMessageDialog(null, e.getMessage(), "Erreur", JOptionPane.ERROR_MESSAGE);
					e.printStackTrace();
				}
			} else {
				JOptionPane.showMessageDialog(null, response, "Erreur serveur distant", JOptionPane.ERROR_MESSAGE);
			}
			
		}
	}
}