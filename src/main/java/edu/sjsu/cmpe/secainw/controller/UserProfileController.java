package edu.sjsu.cmpe.secainw.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import edu.sjsu.cmpe.secainw.dto.UserProfileDto;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.security.UserDetailsImpl;
import edu.sjsu.cmpe.secainw.service.UserService;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/profile")
public class UserProfileController {

    @Autowired
    private UserService userService;

    @GetMapping
    public ResponseEntity<?> getUserProfile(Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        return userService.findById(userDetails.getId())
                .map(user -> ResponseEntity.ok(new UserProfileDto(user)))
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping
    public ResponseEntity<?> updateUserProfile(@RequestBody UserProfileDto profileDto, Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        return userService.findById(userDetails.getId())
                .map(user -> {
                    User updatedUser = userService.updateUserProfile(user, profileDto.getFirstName(), profileDto.getLastName(), profileDto.getEmail());
                    return ResponseEntity.ok(new UserProfileDto(updatedUser));
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
