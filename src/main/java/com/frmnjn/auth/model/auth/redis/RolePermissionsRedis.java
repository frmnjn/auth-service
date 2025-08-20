package com.frmnjn.auth.model.auth.redis;

import com.frmnjn.auth.model.auth.Permission;
import lombok.Generated;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import java.util.Set;

@Setter
@Getter
@Generated
@RedisHash(value = "role")
public class RolePermissionsRedis {
  @Id
  private String roleId;
  private Set<Permission> permissions;
  private Long createdAt;
  private Long updatedAt;
  @TimeToLive
  private long time;
  private long expiredAt;

}
