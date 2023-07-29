package com.schoolAdmin.repo;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.schoolAdmin.entity.ERole;
import com.schoolAdmin.entity.Role;

public interface RoleRepository extends MongoRepository<Role, String> {
	
	Optional<Role> findByName(ERole role);
}
