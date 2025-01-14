package com.springsecurity.springsecurity.dto;


public class RegisterRequest {

    private String firstname;
    private String lastname;
    private String email;
    private String password;



    public RegisterRequest(String firstname, String lastname, String email, String password) {
         this.firstname = firstname;
         this.lastname = lastname;
         this.email = email;
         this.password = password;
    }
    public RegisterRequest(){

    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }


    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }
   
    
}
