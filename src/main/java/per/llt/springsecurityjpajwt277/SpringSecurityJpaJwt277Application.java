package per.llt.springsecurityjpajwt277;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import per.llt.springsecurityjpajwt277.model.AppRole;
import per.llt.springsecurityjpajwt277.model.AppUser;
import per.llt.springsecurityjpajwt277.service.UserApplicationService;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityJpaJwt277Application {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJpaJwt277Application.class, args);
    }


    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Automatically run when the application starts
     **/

    @Bean
    CommandLineRunner run(UserApplicationService service) {
        return args -> {
            /*
            /** Need to run at once **/
            /** Data save to Mysql Database(Role Table) **/


            service.saveRole(new AppRole(null, "ROLE_USER"));
            service.saveRole(new AppRole(null, "ROLE_MANAGER"));
            service.saveRole(new AppRole(null, "ROLE_ADMIN"));
            service.saveRole(new AppRole(null, "ROLE_SUPER_ADMIN"));


            /** Data save to Mysql Database(User Table) **/


            service.saveUser(new AppUser(null, "LINN LAT HTUN", "linnlathtun279@gmial.com", "123456", new ArrayList<>()));
            service.saveUser(new AppUser(null, "AYE AYE", "ayeaye@gmial.com", "123456", new ArrayList<>()));
            service.saveUser(new AppUser(null, "MOE MOE", "moemoe@gmial.com", "123456", new ArrayList<>()));
            service.saveUser(new AppUser(null, "SU SU", "susu@gmial.com", "123456", new ArrayList<>()));
            service.saveUser(new AppUser(null, "YU YU", "yuyu@gmial.com", "123456", new ArrayList<>()));
            service.saveUser(new AppUser(null, "SHI SHI", "shishi@gmial.com", "123456", new ArrayList<>()));


            /** Data save to Mysql Database(Joining Table that is connected to User and Role Tables) **/


            service.addRoleToUser("LINN LAT HTUN", "ROLE_SUPER_ADMIN");
            service.addRoleToUser("SHI SHI", "ROLE_USER");


        };


    }


}
