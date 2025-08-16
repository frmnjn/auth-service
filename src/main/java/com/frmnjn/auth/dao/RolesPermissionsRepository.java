package com.frmnjn.auth.dao;

import com.frmnjn.auth.model.auth.RolesPermissions;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Set;

public interface RolesPermissionsRepository extends JpaRepository<RolesPermissions, Long> {
  Set<RolesPermissions> findByRoleId(Long roleId);
}
