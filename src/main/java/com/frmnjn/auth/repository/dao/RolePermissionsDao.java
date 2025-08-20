package com.frmnjn.auth.repository.dao;

import com.frmnjn.auth.model.auth.Permission;
import com.frmnjn.auth.model.auth.redis.RolePermissionsRedis;
import com.frmnjn.auth.repository.redis.RolePermissionsRedisRepository;
import com.frmnjn.auth.repository.view.RolesPermissionsViewRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class RolePermissionsDao {
  private final RolePermissionsRedisRepository rolePermissionsRedisRepository;
  private final RolesPermissionsViewRepository rolesPermissionsViewRepository;
  private static final long TTL_ROLE_MILLIS = 60 * 60 * 24 * 1000L;
  private static final long TTL_ROLE_SECOND = 60 * 60 * 24L;

  public Set<Permission> getPermissionsByRoleId(Long roleId) {
    RolePermissionsRedis rolePermissionsRedis = rolePermissionsRedisRepository.findById(String.valueOf(roleId)).orElse(null);
    if (rolePermissionsRedis != null) {
      log.info("roleId : {} - getPermissionsByRoleId rolePermissionsRedis found", roleId);
      return rolePermissionsRedis.getPermissions();
    }

    Set<Permission> permissions = rolesPermissionsViewRepository.findByRoleId(roleId)
        .stream().map(Permission::new)
        .collect(Collectors.toSet());

    long currentTime = System.currentTimeMillis();
    rolePermissionsRedis = new RolePermissionsRedis();
    rolePermissionsRedis.setRoleId(String.valueOf(roleId));
    rolePermissionsRedis.setPermissions(permissions);
    rolePermissionsRedis.setCreatedAt(currentTime);
    rolePermissionsRedis.setExpiredAt(currentTime + TTL_ROLE_MILLIS);
    rolePermissionsRedis.setTime(TTL_ROLE_SECOND);
    log.info("roleId : {} - getPermissionsByRoleId rolePermissionsRedis inserted", roleId);
    rolePermissionsRedisRepository.save(rolePermissionsRedis);
    return permissions;
  }
}
