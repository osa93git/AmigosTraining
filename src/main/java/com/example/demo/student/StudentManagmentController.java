package com.example.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays; 
import java.util.List;

@RestController
@RequestMapping("managment/api/v1/students")

public class StudentManagmentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );

    // hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permission')
    //TODO: GODZINA i 56 min 1:56

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')")
    public List<Student> getAllStudents() {
        System.out.println("getStudents");
        return STUDENTS;
    }
    @PostMapping
    @PreAuthorize(("hasAuthority('student:write')"))
    public void registerNewStudent( @RequestBody Student student){
        System.out.println("registerNewStudent");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize(("hasAuthority('student:write')"))
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println("deleteNewStudent");
        System.out.println(studentId);
    }

    @PutMapping(path="{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student){
        System.out.println("update");
        System.out.printf("%s %s", studentId, student);
    }

}
