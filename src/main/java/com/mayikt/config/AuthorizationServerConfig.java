package com.mayikt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * @ClassName: AuthorizationServerConfig
 * @description: 授权认证服务中心
 * @author: gjm
 * @date: 2020-05-01 22 41
 **/
@Configuration
@EnableAuthorizationServer //开启授权认证中心
public class AuthorizationServerConfig extends
		AuthorizationServerConfigurerAdapter {

	//token 有效期 1000：单位（秒）
	private static  final int ACCESSTOKENVALIDITYSECONDS =7200;
	//token 有效期 1000：单位（秒）
	private static  final int REFRESHTOKENVALIDITYSECONDS =7200;


	@Override public void configure(ClientDetailsServiceConfigurer clients)
			throws Exception {
		// @formatter:off
		clients.inMemory().withClient("client_1").secret(
				passwordEncode().encode("123456"))
				.redirectUris("http://www.baidu.com")
				.authorizedGrantTypes("authorization_code","password","refresh_token")
				.scopes("all")
		        .accessTokenValiditySeconds(ACCESSTOKENVALIDITYSECONDS).refreshTokenValiditySeconds(REFRESHTOKENVALIDITYSECONDS);


	}

	//设置token类型
	//@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints){
		endpoints.authenticationManager(authenticationManager())
				.allowedTokenEndpointRequestMethods(HttpMethod.GET,HttpMethod.POST);
		//endpoints.authenticationManager(a)
		endpoints.userDetailsService(userDetailsService());
	}

	@Bean
	AuthenticationManager authenticationManager(){
		AuthenticationManager authenticationManager = new AuthenticationManager(){

			@Override public Authentication authenticate(
					Authentication authentication)
					throws AuthenticationException {
				return daoAuthenticationProvider().authenticate(authentication);
			}
		};
		return authenticationManager;
	}
	@Override public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
		//允许表单认证
		oauthServer.allowFormAuthenticationForClients();
		//允许check_token认证
		oauthServer.checkTokenAccess("permitAll()");

	}

	@Bean public AuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(userDetailsService());
		daoAuthenticationProvider.setHideUserNotFoundExceptions(false);
		daoAuthenticationProvider.setPasswordEncoder(passwordEncode());
		return daoAuthenticationProvider;
	}


	@Bean public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
		userDetailsService.createUser(User.withUsername("user_1").password(passwordEncode().encode("123456"))
		.authorities("ROLE_USER").build());
		userDetailsService.createUser(User.withUsername("user_2").password(passwordEncode().encode("1234567"))
				.authorities("ROLE_USER").build());
		return userDetailsService;
	}

	@Bean
	public PasswordEncoder passwordEncode(){
		//加密方式
		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		return passwordEncoder;
	}


}
