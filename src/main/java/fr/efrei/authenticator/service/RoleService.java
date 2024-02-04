package fr.efrei.authenticator.service;

import fr.efrei.authenticator.model.Role;
import org.springframework.security.core.Authentication;

import java.util.Set;

public interface RoleService {

    public Set<Role> basicRoles();

    public Set<Role> adaptRoles(Set<String> incomingRoles);

    public Set<Role> AddRolesIfAdmin(Authentication authentication, Set<String> stringRoles);
}
