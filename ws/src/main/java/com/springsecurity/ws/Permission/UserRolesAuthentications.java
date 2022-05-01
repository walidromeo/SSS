package com.springsecurity.ws.Permission;


public enum UserRolesAuthentications {
    USER_PERMISSIONS("user:read","review:create","review:update"),
    MANAGER_PERMISSIONS("user:read", "user:update"),
    ADMIN_PERMISSIONS("user:read", "user:create", "user:update"),
    ROLE_SUPER_ADMIN("user:read", "user:create", "user:update", "user:delete" );

    private String[] authorities;

    UserRolesAuthentications(String... authorities) {
        this.authorities = authorities;
    }

    public String[] getAuthorities() {
        return authorities;
    }
}
