package per.llt.springsecurityjpajwt277.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import per.llt.springsecurityjpajwt277.model.AddRoleToUserRequest;
import per.llt.springsecurityjpajwt277.model.AppRole;
import per.llt.springsecurityjpajwt277.model.AppUser;
import per.llt.springsecurityjpajwt277.service.UserApplicationService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;


import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author: Linn Lat Htun
 * @created: 1/1/2023
 * @project: spring-security-jpa-jwt-277
 * @package: per.llt.springsecurityjpajwt277.controller
 */

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api")
public class UserApplicationController {
    private final UserApplicationService service;


    @GetMapping("/getAllUsers")
    public ResponseEntity<List<AppUser>> getAllUsers() {
        ResponseEntity response = service.loadUsers();
        return response;
    }

    @PostMapping("/user/save")
    public ResponseEntity saveUser(@RequestBody AppUser appUser) {
        // URI uri=URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        // return ResponseEntity.created(uri).body(service.saveUser());
        return service.saveUser(appUser);
    }

    @PostMapping("/role/save")
    public ResponseEntity saveRole(@RequestBody AppRole role) {
        return service.saveRole(role);
    }

    @PostMapping("/role/addToUser")
    public ResponseEntity addRoleToUser(@RequestBody AddRoleToUserRequest request) {
        return service.addRoleToUser(request.getName(), request.getRole());
    }

    @GetMapping("/token/refresh")
    public void refresh(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        Map<String, String> errors = new HashMap<>();
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                String username = decodedJWT.getSubject();
                ResponseEntity user = service.loadUser(username);
                AppUser appUser = (AppUser) user.getBody();

                String access_token = JWT.create()
                        /** user email can add instead of username **/
                        .withSubject(appUser.getUserName())
                        /**  Set Time 3 minutes to Milliseconds **/
                        .withExpiresAt(new Date(System.currentTimeMillis() + 3 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getRoleLists().stream().map(AppRole::getRoleName).collect(Collectors.toList())).
                        sign(algorithm);

                /**Collection<AppRole> appRoleCollection = appUser.getRoleLists();
                 List<String> str = appRoleCollection.stream().map(AppRole::getRoleName).collect(Collectors.toList());

                 List<String> roles = appUser.getRoleLists().stream().map(
                 AppRole::getRoleName
                 ).collect(Collectors.toList());
                 **/

                response.setContentType(APPLICATION_JSON_VALUE);
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);

                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            } catch (Exception e) {
                log.error("Authorization Header is something wrong!!!: {}", authorizationHeader);
                log.error("Authorization Header is something wrong!!!: {}", e.getMessage());
                errors.put("error_message", e.getMessage());

                response.setContentType(APPLICATION_JSON_VALUE);

                new ObjectMapper().writeValue(response.getOutputStream(), errors);

            }

        } else {
            log.error("Refresh Token is Missing!!!");
            errors.put("error_message", new RuntimeException("Refresh Token is Missing").toString());
            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), errors);
        }
    }

}
