package io.security.springsecuritypractice.service;


import io.security.springsecuritypractice.domain.Account;
import io.security.springsecuritypractice.repository.UserRepository;


public interface UserService {


    void createUser(Account account);

}
