package fr.efrei.authenticator.configuration;

import fr.efrei.authenticator.model.ERole;
import fr.efrei.authenticator.security.filter.AuthTokenFilter;
import fr.efrei.authenticator.service.TokenService;
import fr.efrei.authenticator.service.impl.JwtTokenServiceImpl;
import fr.efrei.authenticator.service.impl.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableMethodSecurity(
        prePostEnabled = true
)
public class WebSecurityConfig {

    private UserDetailsService userDetailsService;

    private TokenService tokenService;

    public WebSecurityConfig(
            UserDetailsServiceImpl userDetailsService,
            JwtTokenServiceImpl tokenService
    ){
        this.userDetailsService = userDetailsService;
        this.tokenService = tokenService;
    }

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(){
        return new AuthTokenFilter(tokenService ,userDetailsService);
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(passwordEncoder());
        authProvider.setUserDetailsService(userDetailsService);

        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("*")); //add domains names
        configuration.setAllowedMethods(Arrays.asList("GET", "POST"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(authenticationProvider())
                .authorizeHttpRequests((auth) ->
                        auth
                                .requestMatchers(
                                        HttpMethod.POST,
                                        "/api/auth/signin",
                                        "/api/auth/signup"
                                ).permitAll()
                                .requestMatchers(
                                        HttpMethod.GET,
                                        "/api/auth/get-public-key"
                                ).permitAll()
                                .requestMatchers(
                                        HttpMethod.GET,
                                        "/swagger-ui.html",
                                        "/swagger-ui/*",
                                        "/api-docs/swagger-config",
                                        "/api-docs"
                                ).permitAll()
                                .requestMatchers(
                                        HttpMethod.PUT,
                                        "/api/auth/*/roles"
                                ).hasRole("ADMIN")
                        )
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable); //for the moment

        return http.build();
    }
}
