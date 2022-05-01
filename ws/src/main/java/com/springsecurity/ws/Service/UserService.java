package com.springsecurity.ws.Service;

import com.springsecurity.ws.Exception.*;
import com.springsecurity.ws.Entity.UsersAccount;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    UsersAccount register(String firstName, String lastName, String username, String email, String password) throws UsernameNotExist, UsernameExist, EmailExist, MessagingException, PasswordValidException;

    List<UsersAccount> getUsers();

    UsersAccount findByUsername(String username);

    UsersAccount findByEmail(String email);

    UsersAccount addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive) throws UsernameNotExist, UsernameExist, EmailExist, IOException;

    UsersAccount updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive) throws UsernameNotExist, UsernameExist, EmailExist, IOException;
    void deleteUser(String username) throws IOException;
    void changepassword(UsersAccount user, String newpassword) throws MessagingException, PasswordValidException;

    void resetPassword(String email) throws MessagingException, EmailNotExist;

}
