package com.springsecurity.ws.Implementation;

import com.springsecurity.ws.Exception.*;
import com.springsecurity.ws.Entity.UserData;
import com.springsecurity.ws.Entity.UsersAccount;
import com.springsecurity.ws.Permission.UserRolesAuthentications;
import com.springsecurity.ws.Repository.UsersAccountRepository;
import com.springsecurity.ws.Service.LoginAttempts;
import com.springsecurity.ws.Service.ServiceAllEmail;
import com.springsecurity.ws.Service.UserService;
import lombok.SneakyThrows;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.cryptacular.bean.EncodingHashBean;
import org.cryptacular.spec.CodecSpec;
import org.cryptacular.spec.DigestSpec;
import org.passay.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.transaction.Transactional;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static com.springsecurity.ws.Permission.UserRolesAuthentications.ROLE_SUPER_ADMIN;
import static com.springsecurity.ws.Permission.UserRolesAuthentications.ROLE_SUPER_ADMIN;
import static org.apache.commons.lang3.StringUtils.EMPTY;

@Service
@Transactional
@Qualifier("UserService")
public class UserServiceImplementation implements UserService, UserDetailsService{
    private Logger LOGGER = LoggerFactory.getLogger(getClass());
    private UsersAccountRepository userAcountRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private LoginAttempts loginAttemptService;
    private ServiceAllEmail emailService;
    private UserService userService;



    @Autowired
    public UserServiceImplementation(UsersAccountRepository userAcountRepository, BCryptPasswordEncoder bCryptPasswordEncoder, LoginAttempts loginAttemptService, ServiceAllEmail emailService) {
        this.userAcountRepository = userAcountRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.loginAttemptService = loginAttemptService;
        this.emailService = emailService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UsersAccount user = userAcountRepository.findByUsername(username);
        if (user == null) {
            LOGGER.error("No user found by username: " + username);
            throw new UsernameNotFoundException("No user found by username:" + username);
        } else {
            UserLoginAttemptValidation(user);

            userAcountRepository.save(user);
            UserData userData = new UserData(user);
            LOGGER.info("The user ( " + username + " ) found l9inah hhhh ");
            return userData;
        }
    }
    private void UserLoginAttemptValidation(UsersAccount user) {
        // handling
        if(user.isNotLocked()) {
            if(loginAttemptService.userOverpassMaxAttempts(user.getUsername())) {
                user.setNotLocked(false);
            } else {
                user.setNotLocked(true);
            }
        } else {
            loginAttemptService.RemoveUserAttemptFromCache(user.getUsername());
        }
    }

    @Override
    public UsersAccount register(String firstName, String lastName, String username, String email, String password)
            throws UsernameNotExist, UsernameExist, EmailExist, MessagingException, PasswordValidException {
        isvalidUsernameAndEmail(EMPTY, username, email);

        isValid( password);
        UsersAccount user = new UsersAccount();
        user.setUserId(generateUserId());
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);


        user.setPassword(encodePassword(password));

        user.setActive(true);
        user.setNotLocked(true);
        user.setRole(ROLE_SUPER_ADMIN.name());//ROLE_SUPER_ADMIN
        user.setAuthorities(ROLE_SUPER_ADMIN.getAuthorities());
        userAcountRepository.save(user);
        LOGGER.info("New user password: " + password);
        emailService.sendNewPasswordEmail(firstName, password, email);
        return user;


    }

    private UsersAccount isvalidUsernameAndEmail(String currentUsername, String newUsername, String newEmail) throws UsernameNotExist, UsernameExist, EmailExist {
        UsersAccount userByNewUsername = findByUsername(newUsername);
        UsersAccount userByNewEmail = findByEmail(newEmail);
        if(StringUtils.isNotBlank(currentUsername)) {
            UsersAccount currentUser = findByUsername(currentUsername);
            if(currentUser == null) {
                throw new UsernameNotExist("No user found by username: " + currentUsername);
            }
            if(userByNewUsername != null && !currentUser.getId().equals(userByNewUsername.getId())) {
                throw new UsernameExist("Username already exists");
            }
            if(userByNewEmail != null && !currentUser.getId().equals(userByNewEmail.getId())) {
                throw new EmailExist("Email are already exists");
            }
            return currentUser;
        } else {
            if(userByNewUsername != null) {
                throw new UsernameExist("Username already exists");
            }
            if(userByNewEmail != null) {
                throw new EmailExist("Email are already exists");
            }
            return null;
        }
    }


    @SneakyThrows
    public boolean isValid(String password) {
        String messageTemplate = null;
        Properties props = new Properties();
        InputStream inputStream = getClass()
                .getClassLoader().getResourceAsStream("passay.properties");
        try {
            props.load(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        MessageResolver resolver = new PropertiesMessageResolver(props);

        List<PasswordData.Reference> history = Arrays.asList(
                new PasswordData.HistoricalReference(
                        "SHA256",
                        "j93vuQDT5ZpZ5L9FxSfeh87zznS3CM8govlLNHU8GRWG/9LjUhtbFp7Jp1Z4yS7t"),

                new PasswordData.HistoricalReference(
                        "SHA256",
                        "mhR+BHzcQXt2fOUWCy4f903AHA6LzNYKlSOQ7r9np02G/9LjUhtbFp7Jp1Z4yS7t"),

                new PasswordData.HistoricalReference(
                        "SHA256",
                        "BDr/pEo1eMmJoeP6gRKh6QMmiGAyGcddvfAHH+VJ05iG/9LjUhtbFp7Jp1Z4yS7t")
        );
        EncodingHashBean hasher = new EncodingHashBean(
                new CodecSpec("Base64"),
                new DigestSpec("SHA256"),
                1,
                false);
        PasswordValidator validator = new PasswordValidator(resolver, Arrays.asList(

                new LengthRule(8, 16),

                new CharacterRule(EnglishCharacterData.UpperCase, 1),

                new CharacterRule(EnglishCharacterData.LowerCase, 1),

                new CharacterRule(EnglishCharacterData.Digit, 1),

                new CharacterRule(EnglishCharacterData.Special, 1),


                new WhitespaceRule(),

                new IllegalSequenceRule(EnglishSequenceData.Alphabetical, 3, false),
                new IllegalSequenceRule(EnglishSequenceData.Numerical, 3, false)
                //assad
                ,new DigestHistoryRule(hasher)
                //assad
        ));

        RuleResult result = validator.validate(new PasswordData(password));


        PasswordData data = new PasswordData("P@ssword1", password);//"P@ssword1");
        data.setPasswordReferences(history);
        if (result.isValid() ) {
            return true;
        }
        try {
            if (result.isValid()==false) {
                List<String> messages = validator.getMessages(result);

                messageTemplate = String.join(",", messages);

                System.out.println("Invalid Password: " + validator.getMessages(result));
            }
        } finally {
            throw new PasswordValidException(messageTemplate);

        }

    }


    @Override
    public UsersAccount addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive) throws UsernameNotExist, UsernameExist, EmailExist, IOException {
        isvalidUsernameAndEmail(EMPTY, username, email);
        UsersAccount user = new UsersAccount();
        String password = generatePassword();
        user.setUserId(generateUserId());
        user.setFirstName(firstName);
        user.setLastName(lastName);

        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(encodePassword(password));
        user.setActive(isActive);
        user.setNotLocked(isNonLocked);
        user.setRole(getRoleEnumName(role).name());
        user.setAuthorities(getRoleEnumName(role).getAuthorities());

        userAcountRepository.save(user);

        LOGGER.info("New user password: " + password);
        return user;
    }




    @Override
    public void changepassword(UsersAccount user, String newpassword) throws MessagingException, PasswordValidException{
        isValid( newpassword);
        String encryptedPassword = bCryptPasswordEncoder.encode(newpassword);
        user.setPassword(encryptedPassword);
        userAcountRepository.save(user);
        emailService.sendNewPasswordEmail(user.getFirstName(), newpassword,user.getEmail() );


    }
    @Override
    public UsersAccount updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive) throws UsernameNotExist, UsernameExist, EmailExist, IOException {
        UsersAccount currentUser = isvalidUsernameAndEmail(currentUsername, newUsername, newEmail);
        currentUser.setFirstName(newFirstName);
        currentUser.setLastName(newLastName);
        currentUser.setUsername(newUsername);
        currentUser.setEmail(newEmail);
        currentUser.setActive(isActive);
        currentUser.setNotLocked(isNonLocked);
        currentUser.setRole(getRoleEnumName(role).name());
        currentUser.setAuthorities(getRoleEnumName(role).getAuthorities());
        userAcountRepository.save(currentUser);

        return currentUser;
    }

    @Override
    public void deleteUser(String username) throws IOException {
        UsersAccount user=userAcountRepository.findByUsername(username);
        userAcountRepository.deleteById(user.getId());
    }


    @Override
    public List<UsersAccount> getUsers() {
        return (List<UsersAccount>) userAcountRepository.findAll();
    }

    @Override
    public UsersAccount findByUsername(String username) {
        return userAcountRepository.findByUsername(username);
    }

    @Override
    public UsersAccount findByEmail(String email) {
        return userAcountRepository.findByEmail(email);
    }

    private UserRolesAuthentications getRoleEnumName(String role) {
        return UserRolesAuthentications.valueOf(role.toUpperCase());
    }

    private String encodePassword(String password) {
        return bCryptPasswordEncoder.encode(password);
    }

    private String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(10);
    }

    private String generateUserId() {
        return RandomStringUtils.randomNumeric(10);
    }


    @Override
    public void resetPassword(String email) throws MessagingException, EmailNotExist {
        UsersAccount user = userAcountRepository.findByEmail(email);
        if (user == null) {
            throw new EmailNotExist("No user found for email: " + email);
        }
        String password = generatePassword();
        String encryptedPassword = bCryptPasswordEncoder.encode(password);
        user.setPassword(encryptedPassword);
        userAcountRepository.save(user);
        LOGGER.info("New user password: " + password);
        emailService.sendNewPasswordEmail(user.getFirstName(), password, user.getEmail());
    }


}
