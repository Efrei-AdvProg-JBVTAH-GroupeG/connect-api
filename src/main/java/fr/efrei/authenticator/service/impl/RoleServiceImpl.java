package fr.efrei.authenticator.service.impl;

import fr.efrei.authenticator.model.ERole;
import fr.efrei.authenticator.model.Role;
import fr.efrei.authenticator.repository.RoleRepository;
import fr.efrei.authenticator.security.user.UserDetailsImpl;
import fr.efrei.authenticator.service.RoleService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class RoleServiceImpl implements RoleService {

    private RoleRepository roleRepository;

    public RoleServiceImpl(
            RoleRepository roleRepository
    ){
        this.roleRepository = roleRepository;
    }

    public Set<Role> basicRoles() {
        Set<Role> roles = new HashSet<>();
        roles.add(this.roleRepository.findByName(ERole.ROLE_STUDENT)
                .orElseThrow(() -> new RuntimeException("Error : Role student not found")));
        return roles;
    }

    public Set<Role> adaptRoles(Set<String> incomingRoles) {
        Set<Role> roles = new HashSet<>();

        if (incomingRoles == null) {
            Role userRole = this.roleRepository.findByName(ERole.ROLE_STUDENT)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            incomingRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = this.roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "loc":
                        Role locRole = this.roleRepository.findByName(ERole.ROLE_PROFESSOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(locRole);

                        break;
                    default:
                        Role userRole = this.roleRepository.findByName(ERole.ROLE_STUDENT)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        return roles;
    }

    public Set<Role> AddRolesIfAdmin(Authentication authentication, Set<String> stringRoles) {
        return Optional.ofNullable(authentication)
                .filter(auth -> auth.getPrincipal() instanceof UserDetailsImpl)
                .map(UserDetailsImpl.class::cast)
                .filter(userDetails -> userDetails.getAuthorities().stream()
                        .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().toUpperCase().contains("ADMIN")))
                .map(userDetails -> this.adaptRoles(stringRoles))
                .orElseGet(this::basicRoles);
    }
}
