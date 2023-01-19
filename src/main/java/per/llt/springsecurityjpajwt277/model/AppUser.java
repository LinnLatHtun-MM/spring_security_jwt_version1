package per.llt.springsecurityjpajwt277.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @author: Linn Lat Htun
 * @created: 1/1/2023
 * @project: spring-security-jpa-jwt-277
 * @package: per.llt.springsecurityjpajwt277.model
 */

@Data
@Entity
@Table(name = "user")
@AllArgsConstructor
@NoArgsConstructor
public class AppUser {

    //@Column(name = "user_id")
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    //@Column(name = "user_name")
    private String userName;

    //@Column(name = "email")
    private String email;

    //@Column(name = "password")
    private String password;

    /**
     * LAZY = fetch when needed (eg. when you call getMethod)
     * EAGER = fetch immediately
     **/

    /**
     *
     * FetchType.LAZY = This does not load the relationships unless you invoke it via the getter method.
     *
     * FetchType.EAGER = This loads all the relationships.
     *
     * Pros and Cons of these two fetch types.
     *
     * Lazy initialization improves performance by avoiding unnecessary computation and reduce memory requirements.
     *
     * Eager initialization takes more memory consumption and processing speed is slow.
     * **/

    /**
     * FetchType.EAGER or any other Anti-patterns solutions,
     * So that the session will still be alive at the controller method,
     * but these methods will impact the performance.
     * **/

    /**
     * FetchType.LAZY with a mapper (like MapStruct) to transfer data from Entity to another data object DTO
     * and then send it back to the controller, so there is no exception if the session closed.
     **/
    @ManyToMany(fetch = FetchType.EAGER)/** many users have many roles and one user have many roles vice visa one role has many user**/
    Collection<AppRole> roleLists = new ArrayList<>();

}
