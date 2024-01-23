package fr.efrei.authenticator.util;

import fr.efrei.authenticator.model.ERole;
import fr.efrei.authenticator.model.Role;
import fr.efrei.authenticator.repository.RoleRepository;

import java.util.HashSet;
import java.util.Set;

public class RoleUtil {

    public static Set<Role> adaptRoles(Set<String> incomingRoles, RoleRepository roleRepository) {
        Set<Role> roles = new HashSet<>();

        if (incomingRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_STUDENT)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            incomingRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "loc":
                        Role locRole = roleRepository.findByName(ERole.ROLE_PROFESSOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(locRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_STUDENT)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        return roles;
    }
}
