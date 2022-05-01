package com.springsecurity.ws.Repository;

import com.springsecurity.ws.Entity.UsersAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;

public interface UsersAccountRepository extends CrudRepository<UsersAccount, Long> {

    UsersAccount findByUsername(String username);
    UsersAccount findByEmail(String email);

}
