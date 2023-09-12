package io.security.springsecuritypractice.service.impl;

import io.security.springsecuritypractice.domain.Account;
import io.security.springsecuritypractice.repository.UserRepository;
import io.security.springsecuritypractice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
