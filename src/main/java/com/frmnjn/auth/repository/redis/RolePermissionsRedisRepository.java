package com.frmnjn.auth.repository.redis;

import com.frmnjn.auth.model.auth.redis.RolePermissionsRedis;
import org.springframework.data.repository.CrudRepository;

public interface RolePermissionsRedisRepository extends CrudRepository<RolePermissionsRedis, String> {

}
