package com.restaurant.api.authorizationserver.repository;

import com.restaurant.api.authorizationserver.entity.Group;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface GroupRepository extends JpaRepository<Group, Long> {

}
