package com.amanda.springsecurity.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {
	
	private static final List<Student> STUDENTS = Arrays.asList(
			new Student(1, "James Bond"),
			new Student(2, "Maria Jones"),
			new Student(3, "Ana Diaz")
			);
			
	@GetMapping
	public List<Student> getStudents() {
		return STUDENTS;
	}

	@GetMapping(path = "{id}")
	public Student getStudent(@PathVariable("id")Integer id) {
		return STUDENTS.stream()
				.filter(student -> id.equals(student.getId()))
				.findFirst().orElseThrow(() -> new IllegalStateException("Student " + id + " not found"));
	}
}
