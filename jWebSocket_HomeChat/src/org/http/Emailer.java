package org.http;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

/**
* Simple demonstration of using the javax.mail API.
*
* Run from the command line. Please edit the implementation
* to use correct email addresses and host name.
*/
public final class Emailer {
    public static Properties fMailServerConfig = new Properties();
    
    public Emailer(){
        fetchConfig();
    }

  /**
  * Send a single email.
  */
  public void sendEmail(String aSubject, String aBody){
      sendEmail(
              fMailServerConfig.getProperty("mail.username"),
              fMailServerConfig.getProperty("mail.password"),
              fMailServerConfig.getProperty("mail.to"),
              aSubject,
              aBody
              );
      //if send CC 
      if(fMailServerConfig.getProperty("mail.cc.enabled").equalsIgnoreCase("true")){
          sendEmail(
              fMailServerConfig.getProperty("mail.username"),
              fMailServerConfig.getProperty("mail.password"),
              fMailServerConfig.getProperty("mail.cc.to"),
              aSubject,
              aBody
              );
      }
  }
  
  public void sendEmail(
    final String aFromEmailAddr, final String aFromEmailPass, String aEmailTo, String aSubject, String aBody
  ){
    //Here, no Authenticator argument is used (it is null).
    //Authenticators are used to prompt the user for user
    //name and password.
    Session session = Session.getInstance(fMailServerConfig,
		  new javax.mail.Authenticator() {
                        @Override
			protected PasswordAuthentication getPasswordAuthentication() {
				return new PasswordAuthentication(
                                        aFromEmailAddr,//fMailServerConfig.getProperty("mail.username"), 
                                        aFromEmailPass //fMailServerConfig.getProperty("mail.password")
                                        );
			}
		  });
    
    MimeMessage message = new MimeMessage(session);
    try {
      //the "from" address may be set in code, or set in the
      //config file under "mail.from" ; here, the latter style is used
      //message.setFrom(new InternetAddress(aFromEmailAddr));
      message.addRecipient(
        Message.RecipientType.TO, new InternetAddress(aEmailTo)
      );
      message.setSubject(aSubject);
      message.setText(aBody);
      Transport.send(message);
    }
    catch (MessagingException ex){
      System.out.println("Emailer:[SENDEMAIL] ERROR Cannot send email. " + ex);
    }
  }

  /**
  * Allows the config to be refreshed at runtime, instead of
  * requiring a restart.
  */
  public void refreshConfig() {
    fMailServerConfig.clear();
    fetchConfig();
  }
  
  /**
  * Open a specific text file containing mail server
  * parameters, and populate a corresponding Properties object.
  */
  private void fetchConfig() {
    //This file contains the javax.mail config properties mentioned above.
    String path = "/resources/mail.props";
    
    try {
      InputStream input = getClass().getResourceAsStream(path);
      fMailServerConfig.load(input);
    }
    catch (IOException ex){
      System.out.println("Emailer:[FETCHCONFIG] ERROR Cannot open and load mail server properties file.");
    }
  }
} 