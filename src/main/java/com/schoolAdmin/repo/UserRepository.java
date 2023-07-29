package com.schoolAdmin.repo;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.schoolAdmin.entity.User;

public interface UserRepository extends MongoRepository<User, String>{
	
	 Optional<User> findByUsername(String username);

	  Boolean existsByUsername(String username);

	  Boolean existsByEmail(String email);
	
}
