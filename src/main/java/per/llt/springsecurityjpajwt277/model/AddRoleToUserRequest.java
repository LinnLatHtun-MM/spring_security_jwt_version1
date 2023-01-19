package per.llt.springsecurityjpajwt277.model;

import lombok.Data;

/**
 * @author: Linn Lat Htun
 * @created: 1/1/2023
 * @project: spring-security-jpa-jwt-277
 * @package: per.llt.springsecurityjpajwt277.model
 */

@Data
public class AddRoleToUserRequest {
    private String name;
    private String role;
}
