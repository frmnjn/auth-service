package com.frmnjn.auth.service;

import com.frmnjn.auth.model.auth.Permission;
import com.frmnjn.auth.model.auth.UserData;
import com.frmnjn.auth.repository.UserRepository;
import com.frmnjn.auth.repository.dao.RolePermissionsDao;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserInfoService implements UserDetailsService {

  private final UserRepository userRepository;
  private final RolePermissionsDao rolePermissionsDao;
  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    UserData user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

    Set<GrantedAuthority> authorities = rolePermissionsDao.getPermissionsByRoleId(user.getRole().getId())
        .stream()
        .map(Permission::getName)
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toSet());

    return new User(
        user.getUsername(),
        user.getPasswordHash(),
        user.getIsActive(), // enabled
        true,               // accountNonExpired
        true,               // credentialsNonExpired
        true,               // accountNonLocked
        authorities
    );
  }
}
