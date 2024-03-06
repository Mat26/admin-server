package mat.study.adminservice.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.UUID;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final AdminServerProperties adminServer;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    SavedRequestAwareAuthenticationSuccessHandler successHandler =
        new SavedRequestAwareAuthenticationSuccessHandler();
    successHandler.setTargetUrlParameter("redirectTo");
    successHandler.setDefaultTargetUrl(this.adminServer.getContextPath() + "/");

    http
        .authorizeHttpRequests(request -> request.requestMatchers(
            antMatcher(this.adminServer.getContextPath() + "/assets/**")).permitAll()
        )
        .authorizeHttpRequests(request -> request.requestMatchers(
            antMatcher(this.adminServer.getContextPath() + "/actuator/info")).permitAll()
        )
        .authorizeHttpRequests(request -> request.requestMatchers(
            antMatcher(this.adminServer.getContextPath() + "/actuator/health")).permitAll()
        )
        .authorizeHttpRequests(request -> request.requestMatchers(
            antMatcher(this.adminServer.getContextPath() + "/login")).permitAll().anyRequest().authenticated()
        )
        .formLogin(form -> form.loginPage(this.adminServer.getContextPath() + "/login").successHandler(successHandler))
        .logout(out -> out.logoutUrl(this.adminServer.getContextPath() + "/logout"))
        .httpBasic(Customizer.withDefaults())
        .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .ignoringRequestMatchers(
                new AntPathRequestMatcher(this.adminServer.getContextPath() +
                    "/instances", HttpMethod.POST.toString()),
                new AntPathRequestMatcher(this.adminServer.getContextPath() +
                    "/instances/*", HttpMethod.DELETE.toString()),
                new AntPathRequestMatcher(this.adminServer.getContextPath() + "/actuator/**"))
        )
        .rememberMe(r -> r.key(UUID.randomUUID().toString()).tokenValiditySeconds(1209600));

    return http.build();
  }

}
