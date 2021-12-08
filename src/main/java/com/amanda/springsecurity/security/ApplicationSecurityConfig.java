package com.amanda.springsecurity.security;

import static com.amanda.springsecurity.security.ApplicationUserRole.*;
import static com.amanda.springsecurity.security.ApplicationUserPermission.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	
	private final PasswordEncoder passwordEncoder;
	
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable() // this is bad for production - CROSS SITE REQUEST FORGERY
//		    .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//		    .and()
			.authorizeRequests()
			.antMatchers("/", "/index", "/css/*", "/js/*").permitAll() // whitelists urls
			.antMatchers("/api/**").hasRole(STUDENT.name())
			
			// these are represented with annotations in the controllers
//			.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
			.anyRequest()    // all requests
			.authenticated() // to be authenticated
			.and()
			.httpBasic(); //mechanism we want to enforce; basic authentication
	}

	// UserDetailsService used to retrieve users from database
	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails anadiazuser = User.builder()
			.username("anadiaz") 
			.password(passwordEncoder.encode("password"))
			//.roles(STUDENT.name()) // ROLE_STUDENT role based 
			.authorities(STUDENT.getGrantedAuthorities()) // authority/permission based
			.build();
		
		UserDetails mariajonesuser = User.builder()
				.username("mariajones") 
				.password(passwordEncoder.encode("password"))
				//.roles(ADMIN.name()) // ROLE_ADMIN
				.authorities(ADMIN.getGrantedAuthorities()) // authority/permission based
				.build();
		
		UserDetails jamesbonduser = User.builder()
				.username("jamesbond") 
				.password(passwordEncoder.encode("password"))
				//.roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
				.authorities(ADMINTRAINEE.getGrantedAuthorities()) // authority/permission based
				.build();
		
		return new InMemoryUserDetailsManager(anadiazuser, mariajonesuser, jamesbonduser);
	}
	
	
	
}
