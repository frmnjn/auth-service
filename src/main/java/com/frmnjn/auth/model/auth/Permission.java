package com.frmnjn.auth.model.auth;

import com.frmnjn.auth.model.auth.view.RolesPermissionsView;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;

import java.time.ZonedDateTime;

@Getter
@Setter
@Entity
@Table(name = "permissions")
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class Permission {
  @Id
  @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "permissions_id_gen")
  @SequenceGenerator(name = "permissions_id_gen", sequenceName = "permissions_id_seq", allocationSize = 1)
  @Column(name = "id", nullable = false)
  private Long id;

  @Column(name = "name", nullable = false, length = 100)
  private String name;

  @Column(name = "description", length = Integer.MAX_VALUE)
  private String description;

  @ColumnDefault("CURRENT_TIMESTAMP")
  @Column(name = "created_at")
  private ZonedDateTime createdAt;

  @ColumnDefault("CURRENT_TIMESTAMP")
  @Column(name = "updated_at")
  private ZonedDateTime updatedAt;

  public Permission(RolesPermissionsView rolesPermissionsView) {
    this.id = rolesPermissionsView.getPermissionId();
    this.name = rolesPermissionsView.getPermissionName();
    this.description = rolesPermissionsView.getPermissionDescription();
  }

}