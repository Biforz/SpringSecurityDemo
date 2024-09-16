package org.example.springsecuritydemo.model.role;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public enum Role {
    ADMIN(Set.of(Permission.DEVELOPERS_READ, Permission.DEVELOPERS_WRITE)),
    USER(Set.of(Permission.DEVELOPERS_READ));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    /**
     * SimpleGrantedAuthority - определяет, кто и к чему имеет доступ
     * Конвертация ролей в SimpleGrantedAuthority
     * @return Есть роль, у каждой роли есть Set<Permission>, на их основании получаем GrantedAuthority
     */
    public Set<SimpleGrantedAuthority> getSimpleGrantedAuthority() {
        return getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
    }

}
