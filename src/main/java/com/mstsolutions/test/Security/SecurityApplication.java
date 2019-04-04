package com.mstsolutions.test.Security;

import java.security.Principal;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jayway.jsonpath.JsonPath;

@SpringBootApplication
@EnableOAuth2Sso
@EnableAutoConfiguration
@RestController
public class SecurityApplication extends WebSecurityConfigurerAdapter {

	public static void main(String[] args) {
		HashMap<String, Object> props = new HashMap<>();
		try {
			String vcapServices = System.getenv().get("VCAP_SERVICES");
			Optional<Map<String, Object>> maybeCredentials = parseOAuth2Credentials(vcapServices);
			System.out.println(maybeCredentials
					.orElseThrow(() -> new RuntimeException("Oauth2 credentials not found in VCAP_SERVICES")));

			Map<String, Object> credentials = maybeCredentials.get();
			props.put("security.oauth2.client.clientId", credentials.get("clientId"));
			props.put("security.oauth2.client.clientSecret", credentials.get("secret"));
			props.put("security.oauth2.client.accessTokenUri", credentials.get("oauthServerUrl") + "/token");
			props.put("security.oauth2.client.userAuthorizationUri", credentials.get("oauthServerUrl") + "/authorization");
			props.put("security.oauth2.resource.userInfoUri", credentials.get("oauthServerUrl") + "/userInfo");
			props.put("sample.oauth2.logoutEndpoint",  System.getenv().get("logoutEndpoint"));
			props.put("security.resources.chain.enabled", true);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println(props);
		new SpringApplicationBuilder().sources(SecurityApplication.class).properties(props).run(args);
	}

	@SuppressWarnings("unchecked")
	public static Optional<Map<String, Object>> parseOAuth2Credentials(String vcapServices) {
		if (vcapServices != null) {
			List<Map<String, Object>> services = JsonPath.parse(vcapServices).read("$.*.[?(@.credentials)]",
					List.class);
			return services.stream().filter(o -> {
				Collection<String> tags = (Collection<String>) o.get("tags");
				Collection<String> credentialKeys = ((Map<String, Object>) o.get("credentials")).keySet();
				return (tags != null && tags.contains("oauth2")) || credentialKeys.contains("oauthServerUrl");
			}).findFirst().map(t -> (Map<String, Object>) t.get("credentials"));

		}
		return Optional.empty();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// Configuring Spring security access. For /login, /user, and /userinfo, we need
		// authentication.
		// Logout is enabled.
		// Adding csrf token support to this configurer.
		http.authorizeRequests().antMatchers("/login**", "/user", "/userInfo").authenticated().antMatchers("/test**")
				.permitAll().and().logout().logoutSuccessUrl("/").permitAll().and().csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
	}

	@RequestMapping("/test")
	public String printPros() {
		return "";
	}

	@RequestMapping("/user")
	public Principal user(Principal principal) {
		// Principal holds the logged in user information.
		// Spring automatically populates this principal object after login.
		return principal;
	}

	@RequestMapping("/userInfo")
	public String userInfo(Principal principal) {
		final OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) principal;
		final Authentication authentication = oAuth2Authentication.getUserAuthentication();
		// Manually getting the details from the authentication, and returning them as
		// String.
		return authentication.getDetails().toString();
	}
}
