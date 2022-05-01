package com.springsecurity.ws.Service;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutionException;

import static java.util.concurrent.TimeUnit.MINUTES;

@Service
public class LoginAttempts {

    private com.google.common.cache.LoadingCache<String, Integer> loginAttemptCache;

    public LoginAttempts() {
        super();
        loginAttemptCache = CacheBuilder.newBuilder().expireAfterWrite(1, MINUTES)
                .maximumSize(100).build(new CacheLoader<String, Integer>() {
                    public Integer load(String key) {
                        return 0;
                    }
                });
    }


    public void RemoveUserAttemptFromCache(String username) {

        loginAttemptCache.invalidate(username);
    }
    public void addUserToLoginAttemptCache(String username) {
        int attempts = 0;
        try {
            attempts = 1 + loginAttemptCache.get(username);
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        loginAttemptCache.put(username, attempts);
    }
    public boolean userOverpassMaxAttempts(String username) {
        try {
            return loginAttemptCache.get(username) >= 3;
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return false;
    }
}
