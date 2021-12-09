package com.amanda.springsecurity.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import static com.amanda.springsecurity.security.ApplicationUserRole.*;
import com.amanda.springsecurity.student.Student;
import com.google.common.collect.Lists;


@Repository("fake")
public class FakeApplicationUserServiceDAO implements ApplicationUserDAO {
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public FakeApplicationUserServiceDAO(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
 		return getApplicationUsers() 
 				.stream()
 				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
 				.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUsers() {
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser(
						passwordEncoder.encode("password"),
						"anadiaz",
						STUDENT.getGrantedAuthorities(),
						true,
						true,
						true,
						true
				),
				new ApplicationUser(
						passwordEncoder.encode("password"),
						"mariajones",
						ADMIN.getGrantedAuthorities(),
						true,
						true,
						true,
						true
				),
				new ApplicationUser(
						passwordEncoder.encode("password"),
						"jamesbond",
						ADMINTRAINEE.getGrantedAuthorities(),
						true,
						true,
						true,
						true
				)
						
		);
		return applicationUsers;			
	}

}
