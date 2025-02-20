package dev.allainebenedict.loginPage.model;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;

    // Constructor
    public LoginRequest() {}

    // Getters and Setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
