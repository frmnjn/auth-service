package com.frmnjn.auth.dao;

import com.frmnjn.auth.model.auth.UserData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserData, Integer> {
  Optional<UserData> findByUsername(@Param("username") String username);

}
