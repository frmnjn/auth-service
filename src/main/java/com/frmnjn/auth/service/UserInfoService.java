package com.frmnjn.auth.service;

import com.frmnjn.auth.dao.RolesPermissionsRepository;
import com.frmnjn.auth.dao.UserRepository;
import com.frmnjn.auth.model.auth.RolesPermissions;
import com.frmnjn.auth.model.auth.UserData;
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
  private final RolesPermissionsRepository roleWithPermissionViewRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    UserData user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    Set<RolesPermissions> permissions = roleWithPermissionViewRepository.findByRoleId(user.getRole().getId());
    Set<GrantedAuthority> authorities = permissions.stream()
        .map(RolesPermissions::getPermissionName)
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
