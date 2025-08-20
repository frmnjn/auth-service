package com.frmnjn.auth.repository.view;

import com.frmnjn.auth.model.auth.view.RolesPermissionsView;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Set;

public interface RolesPermissionsViewRepository extends JpaRepository<RolesPermissionsView, Long> {
  Set<RolesPermissionsView> findByRoleId(Long roleId);
}
