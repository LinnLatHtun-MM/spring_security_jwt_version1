package per.llt.springsecurityjpajwt277.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import per.llt.springsecurityjpajwt277.model.AppRole;

/**
 * @author: Linn Lat Htun
 * @created: 1/1/2023
 * @project: spring-security-jpa-jwt-277
 * @package: per.llt.springsecurityjpajwt277.repository
 */

@Repository
public interface RoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByRoleName(String roleName);
}
