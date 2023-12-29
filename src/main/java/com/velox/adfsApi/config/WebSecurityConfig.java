package com.velox.adfsApi.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.opensaml.common.xml.SAMLConstants;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Value("${saml.sp}")
	private String samlAudience;

//	@Value("${saml.entityBaseUrl}")
//	private String entityBaseUrl;
	
	@Autowired
	@Qualifier("saml")
	private SavedRequestAwareAuthenticationSuccessHandler samlAuthSuccessHandler;

	@Autowired
	@Qualifier("saml")
	private SimpleUrlAuthenticationFailureHandler samlAuthFailureHandler;

//	@Autowired
//	private SAMLEntryPoint samlEntryPoint;
//
//	@Autowired
//	private SAMLLogoutFilter samlLogoutFilter;
//
//	@Autowired
//	private SAMLLogoutProcessingFilter samlLogoutProcessingFilter;
//
//	@Autowired
//	private MetadataDisplayFilter metadataDisplayFilter;
	
	@Bean
	public SAMLDiscovery samlDiscovery() {
		SAMLDiscovery idpDiscovery = new SAMLDiscovery();
		idpDiscovery.setIdpSelectionPath("/saml/discovery");
		return idpDiscovery;
	}

	@Autowired
	private SAMLAuthenticationProvider samlAuthenticationProvider;

	@Autowired
	private ExtendedMetadata extendedMetadata;

	@Autowired
	private KeyManager keyManager;

	public MetadataGenerator metadataGenerator() {
		MetadataGenerator metadataGenerator = new MetadataGenerator();
		metadataGenerator.setEntityId(samlAudience);
		metadataGenerator.setExtendedMetadata(extendedMetadata);
		metadataGenerator.setIncludeDiscoveryExtension(false);
		metadataGenerator.setKeyManager(keyManager);
//		metadataGenerator.setRequestSigned(true);
//		metadataGenerator.setWantAssertionSigned(false);
//		metadataGenerator.setAssertionConsumerIndex(1);
//		metadataGenerator.setEntityBaseURL(entityBaseUrl);
		return metadataGenerator;
	}

	@Bean
	public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
		SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
		successLogoutHandler.setDefaultTargetUrl("https://am.indiraivf.in/AssetGrid/");
		return successLogoutHandler;
	}

	@Bean
	public SecurityContextLogoutHandler logoutHandler() {
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setInvalidateHttpSession(true);
		logoutHandler.setClearAuthentication(true);
		return logoutHandler;
	}

	@Bean
	public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
		return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
	}

	@Bean
	public SAMLLogoutFilter samlLogoutFilter() {
		return new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[] { logoutHandler() },
				new LogoutHandler[] { logoutHandler() });
	}
	
	@Bean
	public MetadataDisplayFilter metadataDisplayFilter() {
		return new MetadataDisplayFilter();
	}
	
	@Bean
	public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
		SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
		samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
		samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(samlAuthSuccessHandler);
		samlWebSSOProcessingFilter.setAuthenticationFailureHandler(samlAuthFailureHandler);
		return samlWebSSOProcessingFilter;
	}

	@Bean
	public WebSSOProfileOptions defaultWebSSOProfileOptions() {
		WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
		webSSOProfileOptions.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		webSSOProfileOptions.setIncludeScoping(false);

		return webSSOProfileOptions;
	}
	
	@Bean
	public SAMLEntryPoint samlEntryPoint() {
		SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
		samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
		return samlEntryPoint;
	}
	
	@Bean
	public FilterChainProxy samlFilter() throws Exception {
//		List<SecurityFilterChain> chains = new ArrayList<>();
//		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
//				samlWebSSOProcessingFilter()));
//		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"), metadataDisplayFilter()));
//		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"), samlDiscovery()));
//		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint()));
//		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter()));
//		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
//				samlLogoutProcessingFilter()));
//		return new FilterChainProxy(chains);
		
		List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
                samlEntryPoint()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"),
                samlLogoutFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
                metadataDisplayFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter()));
//        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"),
//                samlWebSSOHoKProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
                samlLogoutProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
        		samlDiscovery()));
        return new FilterChainProxy(chains);
		
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public MetadataGeneratorFilter metadataGeneratorFilter() {
		return new MetadataGeneratorFilter(metadataGenerator());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();

//		http.httpBasic().authenticationEntryPoint((request, response, authException) -> {
//			if (request.getRequestURI().endsWith("auth")) {
//				samlEntryPoint.commence(request, response, authException);
//			} else {
//				response.sendRedirect("/");
//			}
//		});
		
		http
        .httpBasic()
        .authenticationEntryPoint(samlEntryPoint());

		http.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
				.addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
				.addFilterBefore(samlFilter(), CsrfFilter.class);

//		http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
		
		http.authorizeRequests().antMatchers("/", "/saml/*").permitAll().anyRequest().authenticated();
		http.logout().addLogoutHandler((request, response, authentication) -> {
			try {
				response.sendRedirect("/saml/logout");
			} catch (IOException e) {
				e.printStackTrace();
			}
		});
	}

//	@Bean
//	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//		return http.requiresChannel(channel -> channel.anyRequest().requiresSecure())
//				.authorizeRequests(authorize -> authorize.anyRequest().permitAll()).build();
//	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(samlAuthenticationProvider);
	}
}
