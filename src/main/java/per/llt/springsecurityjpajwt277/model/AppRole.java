package per.llt.springsecurityjpajwt277.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

/**
 * @author: Linn Lat Htun
 * @created: 1/1/2023
 * @project: spring-security-jpa-jwt-277
 * @package: per.llt.springsecurityjpajwt277.model
 */

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "role")
public class AppRole {
    //@Column(name = "role_id")
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    //@Column(name = "role_name")
    private String roleName;

}
