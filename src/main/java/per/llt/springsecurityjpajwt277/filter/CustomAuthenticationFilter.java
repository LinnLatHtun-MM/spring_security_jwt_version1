package per.llt.springsecurityjpajwt277.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import per.llt.springsecurityjpajwt277.model.TokenResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author: Linn Lat Htun
 * @created: 1/1/2023
 * @project: spring-security-jpa-jwt-277
 * @package: per.llt.springsecurityjpajwt277.filter
 */
@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        /**
         * Current user of username and password from built-in login api
         * we did override that method and do authenticate for user input username and password and our database username and password
         */
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is: {} and Password is: {}", username, password);

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        Authentication authentication = authenticationManager.authenticate(token);
        return authentication;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        /**
         * after login (user name and password) is successful, this method generate
         * access_token and refresh_token with time limit
         * this method override built in spring-security
         * **/

        /** Get Current User Information**/
        User user = (User) authResult.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        System.out.println("Algorithm with secret is" + algorithm);
        String access_token = JWT.create()
                /** user email can add instead of username **/
                .withSubject(user.getUsername())
                /**  Set Time 1 minutes to Milliseconds **/
                .withExpiresAt(new Date(System.currentTimeMillis() + 1 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())).
                sign(algorithm);


        String refresh_token = JWT.create()
                /** user email can add instead of username **/
                .withSubject(user.getUsername())
                /**  Set Time 3 minutes to Milliseconds for refresh token**/
                .withExpiresAt(new Date(System.currentTimeMillis() + 3 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        // super.successfulAuthentication(request, response, chain, authResult);


        /** response value as header **/
        /* response.setHeader("access_token",access_token);
        response.setHeader("refresh_token",refresh_token); */

        /** Response as Entity **/
        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccess_token(access_token);
        tokenResponse.setRefresh_token(refresh_token);

        /** You Also Use Map to return Response **/
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);

        /** We need to change return response as json **/
        response.setContentType(APPLICATION_JSON_VALUE);

        //Return as Json String, not json.
        /** Don't need to return, token response is bind to response variable with object mapper **/
        new ObjectMapper().writeValue(response.getOutputStream(), tokenResponse);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }


}
