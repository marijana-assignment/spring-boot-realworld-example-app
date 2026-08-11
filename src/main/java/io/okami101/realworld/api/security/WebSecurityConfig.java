package io.okami101.realworld.api.security;

import static java.util.Arrays.asList;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

  @Value("${spring.h2.console.enabled:false}")
  private boolean h2ConsoleEnabled;

  private JwtTokenFilter jwtTokenFilter;

  public WebSecurityConfig(JwtTokenFilter jwtTokenFilter) {
    this.jwtTokenFilter = jwtTokenFilter;
  }

  @Value("${management.server.port:-1}")
  private int managementPort;

  /**
   * Actuator, on its own connector, without authentication.
   *
   * <p>WHY THIS EXISTS: the chain below ends in {@code anyRequest().authenticated()}, and a single
   * SecurityFilterChain covers every connector — so Actuator on the management port answered 401.
   * Kubernetes reads that as a failed probe, so the container started cleanly, served nothing, and
   * was killed 150 seconds later by the startup probe. The event said only "HTTP probe failed with
   * statuscode: 401", which names neither this class nor the port.
   *
   * <p>WHY permitAll IS SAFE HERE, AND WOULD NOT BE ON 8080: this matches on the management port
   * only, which no Ingress routes. It is reachable from inside the cluster — the kubelet for
   * probes, Prometheus for scraping — and from nowhere else. That separation is the entire reason
   * management.server.port is set; on a shared port these endpoints would sit under /api, which
   * CloudFront publishes to the internet.
   *
   * <p>Matching on the port rather than on EndpointRequest.toAnyEndpoint() is deliberate: it
   * depends on nothing but the servlet API, so it does not move when Actuator's packages are
   * reorganised between Spring Boot majors.
   */
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain actuatorFilterChain(HttpSecurity http) throws Exception {
    http.securityMatcher(request -> request.getLocalPort() == managementPort)
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());

    return http.build();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) {

    if (h2ConsoleEnabled) {
      http.authorizeHttpRequests(
              auth -> auth.requestMatchers("/h2-console", "/h2-console/**").permitAll())
          .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));
    }

    http.csrf(csrf -> csrf.disable())
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .exceptionHandling(
            e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers("/docs")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/articles/feed")
                    .authenticated()
                    .requestMatchers(HttpMethod.POST, "/users", "/users/login")
                    .permitAll()
                    .requestMatchers(
                        HttpMethod.GET,
                        "/swagger-ui.html",
                        "/swagger-ui/**",
                        "/v3/**",
                        "/articles/**",
                        "/profiles/**",
                        "/tags",
                        "/")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .addFilterBefore(this.jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  private CorsConfigurationSource corsConfigurationSource() {
    final CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(asList("*"));
    configuration.setAllowedMethods(asList("HEAD", "GET", "POST", "PUT", "DELETE", "PATCH"));
    // setAllowCredentials(true) is important, otherwise:
    // The value of the 'Access-Control-Allow-Origin' header in the response must
    // not be the
    // wildcard '*' when the request's credentials mode is 'include'.
    configuration.setAllowCredentials(false);
    // setAllowedHeaders is important! Without it, OPTIONS preflight request
    // will fail with 403 Invalid CORS request
    configuration.setAllowedHeaders(asList("Authorization", "Cache-Control", "Content-Type"));
    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
}
