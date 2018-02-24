package com.gtigsmart;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

	// get user from the database, via Hibernate
	@Autowired
	private UserRepository userRepository;

	@Transactional(readOnly = true)
	@Override
	public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {

		com.gtigsmart.User user = userRepository.findByUsername(username);
		if (user == null) {
			System.out.println("User not found");
			throw new UsernameNotFoundException("Username not found");
		}
		List<GrantedAuthority> authorities = buildUserAuthority(user.getUserRole());

		return buildUserForAuthentication(user, authorities);

	}

	private List<GrantedAuthority> buildUserAuthority(Set<UserRole> userRoles) {

		Set<GrantedAuthority> setAuths = new HashSet<GrantedAuthority>();

		// Build user's authorities
		for (UserRole userRole : userRoles) {
			setAuths.add(new SimpleGrantedAuthority(userRole.getRole()));
		}

		List<GrantedAuthority> Result = new ArrayList<GrantedAuthority>(setAuths);

		return Result;
	}

	// Converts DB user to
	// org.springframework.security.core.userdetails.User
	private User buildUserForAuthentication(com.gtigsmart.User user, List<GrantedAuthority> authorities) {
		return new User(user.getUsername(), user.getPassword(), user.isEnabled(), true, true, true, authorities);
	}

}