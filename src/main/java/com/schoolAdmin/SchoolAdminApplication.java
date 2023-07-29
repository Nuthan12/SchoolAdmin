package com.schoolAdmin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;


@SpringBootApplication
@ComponentScan(basePackages = "com.schoolAdmin.*")
public class SchoolAdminApplication {

	
	
	public static void main(String[] args) {
		SpringApplication.run(SchoolAdminApplication.class, args);
		
		
	}

}
