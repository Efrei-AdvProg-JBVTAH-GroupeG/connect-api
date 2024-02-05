package fr.efrei.authenticator.runner;

import fr.efrei.authenticator.configuration.properties.BaseDataProperties;
import fr.efrei.authenticator.model.ERole;
import fr.efrei.authenticator.model.Role;
import fr.efrei.authenticator.model.User;
import fr.efrei.authenticator.repository.RoleRepository;
import fr.efrei.authenticator.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Set;

@Component
@Slf4j
public class DataSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;

    private final UserRepository userRepository;

    private final BaseDataProperties baseDataProperties;

    private final PasswordEncoder passwordEncoder;

    public DataSeeder(
            RoleRepository roleRepository,
            UserRepository userRepository,
            BaseDataProperties baseDataProperties,
            PasswordEncoder passwordEncoder
    ) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.baseDataProperties = baseDataProperties;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        EnumSet.allOf(ERole.class).forEach(role -> {
            if (roleRepository.findByName(role).isEmpty()) {
                roleRepository.save(new Role(role));
            }
        });

        //create admin
        ArrayList<User> baseUserList = new ArrayList<>();
        baseUserList.add(new User(
                "Student-demo",
                "student@exemple.com",
                passwordEncoder.encode(baseDataProperties.getBasePassword()),
                Set.of(roleRepository.findByName(ERole.ROLE_STUDENT).orElseThrow())
        ));
        baseUserList.add(new User(
                "Tutor-demo",
                "tutor@exemple.com",
                passwordEncoder.encode(baseDataProperties.getBasePassword()),
                Set.of(roleRepository.findByName(ERole.ROLE_TUTOR).orElseThrow())
        ));
        baseUserList.add(new User(
                "Admin-demo",
                "admin@exemple.com",
                passwordEncoder.encode(baseDataProperties.getBasePassword()),
                Set.of(roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow())
        ));
        for (User user: baseUserList) {
            if (userRepository.findUserByUsername(user.getUsername()).isEmpty()) {
                userRepository.save(user);
            }
        }
    }
}