package com.dataart.resource;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserResource {

    @GetMapping("/principal")
    @PreAuthorize("hasRole('ROLE_USER')")
    @ResponseStatus(HttpStatus.OK)
    public Principal getPrincipal(Principal principal) {
        return principal;
    }

}
