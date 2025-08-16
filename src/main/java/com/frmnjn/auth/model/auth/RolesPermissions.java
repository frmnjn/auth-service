package com.frmnjn.auth.model.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "vw_roles_with_permissions")
@ToString
public class RolesPermissions {

  @Id
  @Column(name = "id")
  private UUID id;

  @Column(name = "role_id")
  private Long roleId;

  @Column(name = "role_name")
  private String roleName;

  @Column(name = "role_description")
  private String roleDescription;

  @Column(name = "permission_id")
  private Long permissionId;

  @Column(name = "permission_name")
  private String permissionName;

  @Column(name = "permission_description")
  private String permissionDescription;
}
