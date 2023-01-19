package per.llt.springsecurityjpajwt277.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import per.llt.springsecurityjpajwt277.model.AppRole;
import per.llt.springsecurityjpajwt277.model.AppUser;
import per.llt.springsecurityjpajwt277.repository.RoleRepository;
import per.llt.springsecurityjpajwt277.repository.UserRepository;

import javax.transaction.Transactional;
import java.util.*;

/**
 * @author: Linn Lat Htun
 * @created: 1/1/2023
 * @project: spring-security-jpa-jwt-277
 * @package: per.llt.springsecurityjpajwt277.service
 */

@Service
@RequiredArgsConstructor// for constructor injection in for final variables
@Transactional
@Slf4j
public class UserApplicationServiceImpl implements UserApplicationService, UserDetailsService {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;

    private final PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = userRepo.findByUserName(username);
        if (user == null) {
            log.error("User not Found in DB!");
            throw new UsernameNotFoundException("User not found in DB");
        } else {
            log.info("User found in DB");
        }

        //User role is empty
        if (user.getRoleLists().isEmpty()) {
            return new User(user.getUserName(), user.getPassword(), new ArrayList<>());
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoleLists().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getRoleName())));
        //return new org.springframework.security.core.userdetails.User(user.getUserName(),user.getPassword(),authorities);
        return new User(user.getUserName(), user.getPassword(), authorities);
    }

    @Override
    public ResponseEntity saveUser(AppUser user) {
        log.info("Saving User : {}", user);
        /** Encoding password for user credentials **/
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        AppUser dbUser = userRepo.save(user);
        if (dbUser == null) {
            log.error("User can't save successfully!!");
        }
        return new ResponseEntity(dbUser, HttpStatus.OK);
    }

    @Override
    public ResponseEntity saveRole(AppRole role) {
        log.info("Saving Role : {}", role);
        AppRole dbRole = roleRepo.save(role);
        if (dbRole == null) {
            log.error("Role can't save successfully!!");
        }
        return new ResponseEntity(dbRole, HttpStatus.OK);
    }

    @Override
    public ResponseEntity addRoleToUser(String username, String roleName) {

        Map<String, String> errorMap = new HashMap<>();
        log.info("Adding role to the user : {} , {}", username, roleName);
        AppUser user = userRepo.findByUserName(username);
        AppRole role = roleRepo.findByRoleName(roleName);

        if (user == null) {
            log.error("Username can't found in DB.");
            errorMap.put("error", "Username can't found in DB.");
            return new ResponseEntity(errorMap, HttpStatus.BAD_REQUEST);

        }
        if (role == null) {
            log.error("RoleName can't found in DB.");
            errorMap.put("error", "RoleName can't found in DB.");
            return new ResponseEntity(errorMap, HttpStatus.BAD_REQUEST);
        }

        /** find role is already belonged to user **/
        Optional roleMatch = user.getRoleLists().stream().filter(x -> x.getRoleName().equals(roleName)).findFirst();


        if (roleMatch.isPresent()) {
            log.error("User's already belong to this role {}", roleName);
            errorMap.put("error", "User's already belong to this role: " + roleName);
            return new ResponseEntity(errorMap, HttpStatus.BAD_REQUEST);
        }

        /**
         *  adding data to user and role tables for joining without saving user and role again that are already exist in db
         *  and if it has error,when joining rollback again
         */
        boolean saveFlag = user.getRoleLists().add(role);
        if (saveFlag != false) {
            log.info("Successfully add role: {} to user: {}", roleName, username);
            return new ResponseEntity("Successfully Save!!", HttpStatus.OK);
        } else {
            log.error("Fail to add role: {} to user: {}", roleName, username);
            errorMap.put("error", "Fail to add to this role: " + roleName);
            return new ResponseEntity(errorMap, HttpStatus.BAD_REQUEST);
        }


    }

    @Override
    public ResponseEntity loadUser(String username) {
        AppUser dbUser = userRepo.findByUserName(username);
        if (dbUser == null) {
            log.error("User doesn't exist in Database!");
        }
        return new ResponseEntity(dbUser, HttpStatus.OK);
    }

    @Override
    public ResponseEntity loadUsers() {
        List<AppUser> userList = userRepo.findAll();
        return new ResponseEntity(userList, HttpStatus.OK);
    }

    @Override
    public ResponseEntity loadRoles() {
        List<AppRole> roleList = roleRepo.findAll();
        return new ResponseEntity(roleList, HttpStatus.OK);
    }


}
