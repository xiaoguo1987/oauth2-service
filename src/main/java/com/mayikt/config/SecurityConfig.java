package com.mayikt.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.stereotype.Component;

/**
 * @author Joe Grandja
 */
@Component
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// 拦截所以请求，使用httpBasic方式登陆
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/**").fullyAuthenticated()
				.and()
				.httpBasic();
	}

}