package com.ahmetemre90.springbootsecurity.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.ahmetemre90.springbootsecurity.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {

        List<ApplicationUser> applicationUsers = Lists.newArrayList(

                new ApplicationUser(
                        "user1",
                        passwordEncoder.encode("123456"),
                        STUDENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true),

                new ApplicationUser(
                        "admin1",
                        passwordEncoder.encode("123456"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true),

                new ApplicationUser(
                        "adminTrainee1",
                        passwordEncoder.encode("123456"),
                        ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true)
        );

        return applicationUsers;
    }
}
