package com.in28minutes.rest.webservices.restfulwebservices.jwt;

import com.in28minutes.rest.webservices.restfulwebservices.services.UserDetailsServiceImpl;
import com.in28minutes.rest.webservices.restfulwebservices.jwt2.AuthEntryPointJwt;
import com.in28minutes.rest.webservices.restfulwebservices.jwt2.AuthTokenFilter;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Import({ UserDetailsServiceImpl.class, AuthEntryPointJwt.class, AuthTokenFilter.class })
public class JWTWebSecurityConfigCopy {
	@Autowired
	UserDetailsServiceImpl userDetailsService;
	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;
	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		// https://github.com/spring-projects/spring-security/issues/1231
		// https://docs.spring.io/spring-boot/docs/current/reference/html/data.html#data.sql.h2-web-console.spring-security
		return httpSecurity
				.authorizeHttpRequests(auth -> auth

						.requestMatchers("/api/test/**","/api/auth/**","/authenticate", "/hello-world", "/hello-world-bean").permitAll()
//						.requestMatchers(PathRequest.toH2Console()).permitAll() // h2-console is a servlet and NOT recommended for a production
						.requestMatchers(HttpMethod.OPTIONS,"/**")
						.permitAll()
						.anyRequest()
						.authenticated()


				)
				.csrf(csrf -> csrf.disable())
				.csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(session -> session.
						sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.oauth2ResourceServer((oauth2) -> oauth2.jwt(withDefaults()))
				.httpBasic(
						withDefaults())
				.headers(header -> header.frameOptions(frameOptionsConfig -> frameOptionsConfig.sameOrigin()))

		.authenticationProvider(authenticationProvider())
		.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)


				.build();
	}

//	@Bean
//	public AuthenticationManager authenticationManager(UserDetailsService userDetailsService) {
//		var authenticationProvider = new DaoAuthenticationProvider();
//		authenticationProvider.setUserDetailsService(userDetailsService);
//
//		return new ProviderManager(authenticationProvider);
//	}

//	@Bean
//	public UserDetailsService userDetailsService() {
//		UserDetails user = User.withUsername("Sneha")
//				.password("{noop}Gupta")
//				.authorities("read")
//				.roles("USER")
//				.build();
////		for admin
//		UserDetails admin = User.withUsername("Preetam")
//				.password("{noop}Lahre")
//				.authorities("read")
//				.roles("ADMIN","USER")
//				.build();
//
//
//
//
//
//		return new InMemoryUserDetailsManager(user,admin);
//	}


	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		JWKSet jwkSet = new JWKSet(rsaKey());

		return (((jwkSelector, securityContext)
				-> jwkSelector.select(jwkSet)));
	}

	@Bean
	JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}

	@Bean
	JwtDecoder jwtDecoder() throws JOSEException {
		return NimbusJwtDecoder
				.withPublicKey(rsaKey().toRSAPublicKey())
				.build();
	}

	@Bean
	public RSAKey rsaKey() {
		KeyPair keyPair = keyPair();

		return new RSAKey
				.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString())
				.build();
	}

	@Bean
	public KeyPair keyPair() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(
					"Unable to generate an RSA Key Pair", e);
		}
	}

}
