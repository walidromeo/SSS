package com.springsecurity.ws.Controller;

import com.springsecurity.ws.Exception.*;
import com.springsecurity.ws.Entity.HTTPProtocolResponse;
import com.springsecurity.ws.Entity.UserData;
import com.springsecurity.ws.Entity.UsersAccount;
import com.springsecurity.ws.Repository.*;
import com.springsecurity.ws.Repository.UsersAccountRepository;
import com.springsecurity.ws.Service.UserService;
import com.springsecurity.ws.Utility.*;
import com.springsecurity.ws.Utility.JWTProvider;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.validation.Valid;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping(path = { "/", "/user"})
public class UserController extends ExceptionProcessing {

    private AuthenticationManager authenticationManager;
    private UserService userService;
    private JWTProvider jWTProvider;
    private UsersAccountRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    public UserController(AuthenticationManager authenticationManager, UserService userService, JWTProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.jWTProvider = jwtTokenProvider;
    }
    @GetMapping("/home")
    public String DisplayUserOnly()  {
        return "WELCOME HOME SPRING";
    }

    @PostMapping("/login")
    public ResponseEntity<UsersAccount> login(@RequestBody UsersAccount user) {
        sssAuth(user.getUsername(), user.getPassword());
        UsersAccount login = userService.findByUsername(user.getUsername());
        UserData userData = new UserData(login);
        HttpHeaders jwtHeader = getasmyJwtHeader(userData);
        return new ResponseEntity<>(login, jwtHeader, OK);
    }


    @PostMapping("/register")
    public ResponseEntity<UsersAccount> register(@Valid @RequestBody UsersAccount userData) throws UsernameNotExist, UsernameExist, EmailExist, MessagingException, PasswordValidException {
        userService.register( userData.getFirstName(), userData.getLastName(), userData.getUsername(), userData.getEmail(),userData.getPassword());
        return new ResponseEntity<>(userData, HttpStatus.OK);
    }

    @PostMapping("/add")
    public ResponseEntity<UsersAccount> addNewUser(@RequestParam("firstName") String firstName,
                                                   @RequestParam("lastName") String lastName,
                                                   @RequestParam("username") String username,
                                                   @RequestParam("email") String email,
                                                   @RequestParam("role") String role,
                                                   @RequestParam("isActive") String isActive,
                                                   @RequestParam("isNonLocked") String isNonLocked)

            throws UsernameNotExist, UsernameExist, EmailExist, IOException {
        UsersAccount newUser = userService.addNewUser(firstName, lastName, username,email, role, Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive));
        return new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/update")
    public ResponseEntity<UsersAccount> update(@RequestParam("currentUsername") String currentUsername,
                                               @RequestParam("firstName") String firstName,
                                               @RequestParam("lastName") String lastName,
                                               @RequestParam("username") String username,
                                               @RequestParam("email") String email,
                                               @RequestParam("role") String role,
                                               @RequestParam("isActive") String isActive,
                                               @RequestParam("isNonLocked") String isNonLocked)

            throws UsernameNotExist, UsernameExist, EmailExist, IOException {
        UsersAccount updatedUser = userService.updateUser(currentUsername, firstName, lastName, username,email, role, Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive));
        return new ResponseEntity<>(updatedUser, OK);
    }

    //assad
    @PostMapping("/changepassword")
    public ResponseEntity<String> changePassword(@RequestBody HashMap<String, String> request) {
        String username = request.get("username");
        UsersAccount user = userService.findByUsername(username);
        if (user == null) {
            return new ResponseEntity<>("User not found!", HttpStatus.BAD_REQUEST);
        }
        String currentPassword = request.get("currentpassword");
        String newPassword = request.get("newpassword");
        String confirmpassword = request.get("confirmpassword");
        if (!newPassword.equals(confirmpassword)) {
            return new ResponseEntity<>("PASSWORD AND CONFIRME PASSWORD DOSENT MATCH", HttpStatus.BAD_REQUEST);
        }
        String userPassword = user.getPassword();
        try {
            if (newPassword != null && !newPassword.isEmpty() && !StringUtils.isEmpty(newPassword)) {
                if (bCryptPasswordEncoder.matches(currentPassword, userPassword)) {
                    userService.changepassword(user, newPassword);
                }
            } else {
                return new ResponseEntity<>("IncorrectCurrentPassword", HttpStatus.BAD_REQUEST);
            }
            return new ResponseEntity<>("Password Changed Successfully!", HttpStatus.OK);
        }
        catch (Exception e) {
            return new ResponseEntity<>("Error Occured: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }


    @DeleteMapping("/delete/{username}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<HTTPProtocolResponse> deleteUser(@PathVariable ("username") String username)throws IOException
    {
        userService.deleteUser(username);
        return response(OK,"User delete successfully");
    }

    @GetMapping("/find/{username}")
    public ResponseEntity<UsersAccount> getUser(@PathVariable("username") String username) {
        UsersAccount user = userService.findByUsername(username);
        return new ResponseEntity<>(user, OK);
    }


    @GetMapping("/list")
    public ResponseEntity<List<UsersAccount>> getAllUsers() {
        List<UsersAccount> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }

    private ResponseEntity<HTTPProtocolResponse> response(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(new HTTPProtocolResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(),
                message), httpStatus);
    }

    private HttpHeaders getasmyJwtHeader(UserData user) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Bearer ", jWTProvider.generateJwtToken(user));
        return headers;
    }

    private void sssAuth(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }


    @GetMapping("/resetpassword/{email}")
    public ResponseEntity<HTTPProtocolResponse> resetPassword(@PathVariable("email") String email) throws MessagingException, EmailNotExist {
        userService.resetPassword(email);
        return response(OK, "An email with a new password was sent to: " + email);
    }

}
