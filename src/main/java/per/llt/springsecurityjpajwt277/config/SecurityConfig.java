package per.llt.springsecurityjpajwt277.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import per.llt.springsecurityjpajwt277.filter.CustomAuthenticationFilter;
import per.llt.springsecurityjpajwt277.filter.CustomAuthorizationFilter;


/**
 * @author: Linn Lat Htun
 * @created: 1/1/2023
 * @project: spring-security-jpa-jwt-277
 * @package: per.llt.springsecurityjpajwt277.config
 */

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder encoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /**
         * This method is used to authenticate username and password in our db.
         * **/
        auth.userDetailsService(userDetailsService).passwordEncoder(encoder);
        // inject BCryptPasswordEncoder to userDetailsService
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());

        /**
         * default for csrf(cross site request forgery) enable in spring security
         * csrf is an attack when user is currently authenticated
         * a successful CSRF attack can force the user to perform state changing requests like transferring funds,
         * changing their email address, and so forth.
         * If the victim is an administrative account, CSRF can compromise the entire web application.
         * **/
        http.csrf().disable();

        /** Set for not to save user session data**/
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        /** allow all permissions for request **/
        //http.authorizeRequests().anyRequest().permitAll();

        /**
         * default login url is http://localhost:8080/spring-security-jwt/login
         * we change to http://localhost:8080/spring-security-jwt/api/login
         **/
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");

        /** allow request for specific route **/
        http.authorizeRequests().antMatchers("/api/login/**","/api/token/refresh/**").permitAll();
        http.authorizeRequests().antMatchers(HttpMethod.GET, "/api/getAllUsers/**").hasAnyAuthority("ROLE_USER");
        http.authorizeRequests().antMatchers(HttpMethod.POST, "/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");

        /** Access every request if you are authenticated **/
        http.authorizeRequests().anyRequest().authenticated();

        /** Need this if you use spring latest version 3.1.0 **/
        //http.addFilter((Filter) new CustomAuthenticationFilter(authenticationManagerBean()));

        http.addFilter(customAuthenticationFilter);


        /**  add our CustomAuthorizationFilter class and UsernamePasswordAuthenticationFilter
         *   for checking Authorization into Spring Security Filter.
         *  we put validation token login in that CustomAuthorizationFilter class
         *  to check (validate) user token is valid or not.
         *  filterBefore means application will check authorization before on every api request and every api process
         **/
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


}
