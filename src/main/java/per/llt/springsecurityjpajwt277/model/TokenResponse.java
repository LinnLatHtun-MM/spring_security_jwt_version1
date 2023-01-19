package per.llt.springsecurityjpajwt277.model;

import lombok.Data;

/**
 * @author: Linn Lat Htun
 * @created: 1/1/2023
 * @project: spring-security-jpa-jwt-277
 * @package: per.llt.springsecurityjpajwt277.model
 */

@Data
public class TokenResponse {
    private String access_token;
    private String refresh_token;
}
