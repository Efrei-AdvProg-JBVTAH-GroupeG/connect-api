package fr.efrei.authenticator.controller;

import fr.efrei.authenticator.model.Role;
import fr.efrei.authenticator.model.User;
import fr.efrei.authenticator.payload.request.RolesRequest;
import fr.efrei.authenticator.payload.response.JwtResponse;
import fr.efrei.authenticator.service.RoleService;
import fr.efrei.authenticator.payload.request.LoginRequest;
import fr.efrei.authenticator.payload.request.SignupRequest;
import fr.efrei.authenticator.payload.response.MessageResponse;
import fr.efrei.authenticator.payload.response.TokenResponse;
import fr.efrei.authenticator.repository.UserRepository;
import fr.efrei.authenticator.service.TokenService;
import fr.efrei.authenticator.service.impl.JwtTokenServiceImpl;
import fr.efrei.authenticator.security.user.UserDetailsImpl;
import fr.efrei.authenticator.service.impl.RoleServiceImpl;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    AuthenticationManager authenticationManager;

    UserRepository userRepository;

    PasswordEncoder encoder;

    TokenService tokenService;

    RoleService roleService;

    public AuthController (
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            TokenService jwtTokenService,
            RoleServiceImpl roleService
    ){
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.encoder = passwordEncoder;
        this.tokenService = jwtTokenService;
        this.roleService = roleService;
    }

    @PostMapping(value = "/signin", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = tokenService.generateToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping(value = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        Set<Role> roles = roleService.AddRolesIfAdmin(
                SecurityContextHolder.getContext().getAuthentication(), signUpRequest.getRole()
        );

        // Create new user's account
        User user = new User(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()),
                roles
        );

        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @GetMapping(value = "/get-public-key")
    public ResponseEntity<?> getPublicKeys(){
        return ResponseEntity.ok(new TokenResponse(
                Base64.getEncoder().encodeToString(tokenService.getPublicKey().getEncoded())
        ));
    }

    @PutMapping(value = "/{userId}/roles")
    public ResponseEntity<?> updateRoles(@PathVariable("userId") String userId,
                                         @Valid @RequestBody RolesRequest rolesStr){
        if (! userRepository.existsById(Long.parseLong(userId))){
            return  ResponseEntity.badRequest().body("Error : id not found");
        }

        Set<Role> roles = roleService.adaptRoles(rolesStr.getRole());
        User user = userRepository.findById(Long.parseLong(userId))
                .orElseThrow();
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok("");
    }
}
