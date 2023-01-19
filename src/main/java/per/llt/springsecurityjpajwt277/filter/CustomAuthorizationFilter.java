package per.llt.springsecurityjpajwt277.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import per.llt.springsecurityjpajwt277.service.UserApplicationService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Autowired
    UserApplicationService userApplicationService;


    //Implement Method
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        /** Check if login api we do filter for authentication at first **/
        if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
            filterChain.doFilter(request, response);
        } else {

            /** Get Header Value form Postman API **/
            String authorizationHeader = request.getHeader(AUTHORIZATION);

            /** Header value must be start with Barer or Something you want to add **/
            /** Eg. (Bearer +token) **/
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                try {

                    /** Get token value from header **/
                    String token = authorizationHeader.substring("Bearer ".length());

                    /** Secret Key you add in Authenticationfilter Class and Authorization Class. They must be same. **/
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

                    /** Verify Jwt **/
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();

                    /** Decode JWT **/
                    DecodedJWT decodedJWT = jwtVerifier.verify(token);

                    /** Get username form jwt or if you want to add Something Like email**/
                    String username = decodedJWT.getSubject();

                    /** Get Roles from Claims that are declared in CustomAuthentication Filter Class **/
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                    if (roles != null && roles.length != 0) {
                        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

                        /** Adding roles to authorities Array**/
                        stream(roles).forEach(role -> {
                            authorities.add(new SimpleGrantedAuthority(role));
                        });

                        /** We need to authenticate again we dont need to know password if user is authenticated**/
                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                new UsernamePasswordAuthenticationToken(username, null, authorities);

                        /** We need to know SpringContext to know to do authorization process  **/
                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                        filterChain.doFilter(request, response);
                    } else {
                        filterChain.doFilter(request, response);
                    }


                    /* int[] intArr = {1, 2, 3, 45};
                    Collection<Integer> integers = new ArrayList<>();

                    stream(intArr).forEach(num -> {
                        integers.add(num);
                    }); */

                } catch (Exception e) {
                    log.error("Authorization Header is something wrong!!!: {}", authorizationHeader);
                    log.error("Authorization Header is something wrong!!!: {}", e.getMessage());
                   /* response.setHeader("Error", e.getMessage());
                   response.setStatus(FORBIDDEN.value());
                    response.sendError(FORBIDDEN.value());*/

                    Map<String, String> errors = new HashMap<>();
                    errors.put("error_message", e.getMessage());

                    response.setContentType(APPLICATION_JSON_VALUE);

                    new ObjectMapper().writeValue(response.getOutputStream(), errors);

                }

            } else {
                throw new RuntimeException("Refresh Token is Missing");
                //filterChain.doFilter(request, response);
            }
        }
    }
}
