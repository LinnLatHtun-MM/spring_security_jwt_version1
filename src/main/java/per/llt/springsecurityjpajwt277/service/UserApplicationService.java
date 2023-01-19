package per.llt.springsecurityjpajwt277.service;

import org.springframework.http.ResponseEntity;
import per.llt.springsecurityjpajwt277.model.AppRole;
import per.llt.springsecurityjpajwt277.model.AppUser;

/**
 * @author: Linn Lat Htun
 * @created: 1/1/2023
 * @project: spring-security-jpa-jwt-277
 * @package: per.llt.springsecurityjpajwt277.service
 */

public interface UserApplicationService {
    ResponseEntity saveUser(AppUser user);
    ResponseEntity saveRole(AppRole role);
    ResponseEntity addRoleToUser(String username,String roleName);
    ResponseEntity loadUser(String username);
    ResponseEntity loadUsers();
    ResponseEntity loadRoles();

}
