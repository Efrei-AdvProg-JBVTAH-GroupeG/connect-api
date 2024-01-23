package fr.efrei.authenticator.repository;

import fr.efrei.authenticator.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String Username);

    Optional<User> findById(Long id);

    Boolean existsByEmail(String email);
}
