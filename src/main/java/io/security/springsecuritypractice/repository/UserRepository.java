package io.security.springsecuritypractice.repository;

import io.security.springsecuritypractice.domain.Account;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


public interface UserRepository extends JpaRepository<Account, Long> {


    @Override
    <S extends Account> S save(S entity);


    Account findByUsername(String username);
}
