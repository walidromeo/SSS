package com.springsecurity.ws.Service;

import com.sun.mail.smtp.SMTPTransport;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Date;
import java.util.Properties;

import static javax.mail.Message.RecipientType.TO;

@Service
public class ServiceAllEmail {

    private  JavaMailSender mailSender;

    public void sendNewPasswordEmail(String firstName, String password, String email) throws MessagingException {
        Message message = createEmail(firstName, password, email);
        SMTPTransport smtpTransport = (SMTPTransport) getEmailSession().getTransport("smtps");
        // email who will send the email exemple
        // CREDENTIAL MAIL
        // You Must be change this line
        smtpTransport.connect("smtp.example.com", "example@example.com", "password");
        smtpTransport.sendMessage(message, message.getAllRecipients());
        smtpTransport.close();
    }

    private Message createEmail(String firstName, String password, String email) throws MessagingException {
        Message message = new MimeMessage(getEmailSession());
        // message.setFrom(new InternetAddress("email@gmail.com"));
        message.setFrom(new InternetAddress("example@example.com"));
        message.setRecipients(TO, InternetAddress.parse(email, false));
        message.setSubject("SSS, - New Password");
        message.setText("Hello " + firstName + ", \n \n Your new account password is: " + password + "\n \n The Support Team"+"\n From SSS");
        message.setSentDate(new Date());
        message.saveChanges();
        return message;
    }

    private Session getEmailSession() {
        Properties properties = System.getProperties();
     //   properties.put("mail.smtp.host", "smpt.exemple.example");
        properties.put("mail.smtp.host", "smtp.example.com");
        properties.put("mail.smtp.auth", true);
        properties.put("mail.smtp.port", 465);
        properties.put("mail.smtp.starttls.enable", true);
        properties.put("mail.smtp.starttls.required", true);
        return Session.getInstance(properties, null);
    }





}
