package com.boot3.springSecurity.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.boot3.springSecurity.model.Roles;

// Commented out this configuration as we are using JWT authentication.
//This can be used for default SpringBoot basic configuration
//@Configuration
public class BasicAuthSecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
		// Disabling session by making session Policy Stateless
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		// Disable form login & logout.
		// http.formLogin(withDefaults());

		http.csrf().disable();
// By default, Spring security disable the frame. TO run the H2 database we need to enable it as H2 database is designed based upon frame only.
		http.headers().frameOptions().sameOrigin();

		// We will have basic auth pop-up.
		http.httpBasic(withDefaults());
		return http.build();
	}

	/**
	 * Creating the user , password & roles in memory only
	 * 
	 * @Bean public UserDetailsService userDetailService() {
	 * 
	 *       var user =
	 *       User.withUsername("user").password("{noop}user").roles(Roles.USER.toString()).build();
	 *       var admin =
	 *       User.withUsername("admin").password("{noop}admin").roles(Roles.ADMIN.toString()).build();
	 *       return new InMemoryUserDetailsManager(user, admin); }
	 **/
	// JdbcDaoImpl in SpringBoot package has user.ddl
	// Creating bean to execute the script at the time of application up
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION).build();
	}

	// User details will be stored in the H2 database

	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		var user = User.withUsername("user")
				// password without encoding.
				// .password("{noop}user")
				.password("user").passwordEncoder(str -> passwordEncoder().encode(str)).roles(Roles.USER.toString())
				.build();
		var admin = User.withUsername("admin")
				// password without encoding.
				// .password("{noop}admin")
				.password("admin").passwordEncoder(str -> passwordEncoder().encode(str)).roles(Roles.ADMIN.toString())
				.build();
		var jdbcUserDetailManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailManager.createUser(user);
		jdbcUserDetailManager.createUser(admin);
		return jdbcUserDetailManager;
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
