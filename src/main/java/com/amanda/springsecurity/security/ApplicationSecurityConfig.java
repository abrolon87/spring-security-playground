package com.amanda.springsecurity.security;

import static com.amanda.springsecurity.security.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

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
			.authorizeRequests()
			.antMatchers("/", "/index", "/css/*", "/js/*").permitAll() // whitelists urls
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()    // all requests
			.authenticated() // to be authenticated
			.and()
			.formLogin()
				.loginPage("/login").permitAll()
				// login form parameters on html form
				.passwordParameter("password")
				.usernameParameter("username")
			.defaultSuccessUrl("/courses", true)
			.and()
			.rememberMe() //defaults to 2 weeks
//			.rememberMe().tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) //to remember for 21 days
//			.key("somethingverysecured")
			// remember me parameter on html form
				.rememberMeParameter("remember-me")
			
			.and() 
			.logout()  
				.logoutUrl("/logout")
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID", "remember-me")
				.logoutSuccessUrl("/login")
			;
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
