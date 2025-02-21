package com.restaurant.api.authorizationserver.repository;

import com.restaurant.api.authorizationserver.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

}
