package edu.sjsu.cmpe.secainw.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import edu.sjsu.cmpe.secainw.dto.LoginRequest;
import edu.sjsu.cmpe.secainw.dto.SignupRequest;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.security.UserDetailsImpl;
import edu.sjsu.cmpe.secainw.service.UserService;
import edu.sjsu.cmpe.secainw.util.JwtUtils;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserService userService;

    @Mock
    private JwtUtils jwtUtils;

    @Autowired
    private ObjectMapper objectMapper;

    private LoginRequest loginRequest;
    private SignupRequest signupRequest;
    private User testUser;
    private UserDetailsImpl userDetails;

    @BeforeEach
    void setUp() {
        loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password123");

        signupRequest = new SignupRequest();
        signupRequest.setUsername("newuser");
        signupRequest.setEmail("newuser@example.com");
        signupRequest.setFirstName("New");
        signupRequest.setLastName("User");
        signupRequest.setPassword("password123");
        signupRequest.setRole("ANALYST");

        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setEmail("test@example.com");
        testUser.setFirstName("Test");
        testUser.setLastName("User");
        testUser.setRole(User.Role.ANALYST);

        userDetails = UserDetailsImpl.build(testUser);
    }

    @Test
    void signIn_ShouldReturnJwtResponse_WhenCredentialsAreValid() throws Exception {
        // Arrange
        Authentication authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(jwtUtils.generateJwtToken(authentication)).thenReturn("jwt-token");
        doNothing().when(userService).updateLastLogin(anyString());
        when(userService.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // Act & Assert
        mockMvc.perform(post("/api/auth/signin")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-token"))
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.role").value("ANALYST"));

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtUtils).generateJwtToken(authentication);
        verify(userService).updateLastLogin("testuser");
    }

    @Test
    void signIn_ShouldReturnBadRequest_WhenCredentialsAreInvalid() throws Exception {
        // Arrange
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new RuntimeException("Invalid credentials"));

        // Act & Assert
        mockMvc.perform(post("/api/auth/signin")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Error: Invalid username or password!"))
                .andExpect(jsonPath("$.type").value("error"));

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtUtils, never()).generateJwtToken(any());
    }

    @Test
    void signUp_ShouldReturnSuccess_WhenRequestIsValid() throws Exception {
        // Arrange
        when(userService.existsByUsername("newuser")).thenReturn(false);
        when(userService.existsByEmail("newuser@example.com")).thenReturn(false);
        when(userService.createUser(any(SignupRequest.class))).thenReturn(testUser);

        // Act & Assert
        mockMvc.perform(post("/api/auth/signup")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User registered successfully!"))
                .andExpect(jsonPath("$.type").value("success"));

        verify(userService).existsByUsername("newuser");
        verify(userService).existsByEmail("newuser@example.com");
        verify(userService).createUser(any(SignupRequest.class));
    }

    @Test
    void signUp_ShouldReturnBadRequest_WhenUsernameExists() throws Exception {
        // Arrange
        when(userService.existsByUsername("newuser")).thenReturn(true);

        // Act & Assert
        mockMvc.perform(post("/api/auth/signup")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Error: Username is already taken!"))
                .andExpect(jsonPath("$.type").value("error"));

        verify(userService).existsByUsername("newuser");
        verify(userService, never()).createUser(any(SignupRequest.class));
    }

    @Test
    void signUp_ShouldReturnBadRequest_WhenEmailExists() throws Exception {
        // Arrange
        when(userService.existsByUsername("newuser")).thenReturn(false);
        when(userService.existsByEmail("newuser@example.com")).thenReturn(true);

        // Act & Assert
        mockMvc.perform(post("/api/auth/signup")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Error: Email is already in use!"))
                .andExpect(jsonPath("$.type").value("error"));

        verify(userService).existsByUsername("newuser");
        verify(userService).existsByEmail("newuser@example.com");
        verify(userService, never()).createUser(any(SignupRequest.class));
    }

    @Test
    @WithMockUser
    void signOut_ShouldReturnSuccess() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/api/auth/signout")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User signed out successfully!"))
                .andExpect(jsonPath("$.type").value("success"));
    }

    @Test
    void signIn_ShouldReturnBadRequest_WhenRequestIsInvalid() throws Exception {
        // Arrange
        LoginRequest invalidRequest = new LoginRequest();
        // Missing username and password

        // Act & Assert
        mockMvc.perform(post("/api/auth/signin")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void signUp_ShouldReturnBadRequest_WhenRequestIsInvalid() throws Exception {
        // Arrange
        SignupRequest invalidRequest = new SignupRequest();
        // Missing required fields

        // Act & Assert
        mockMvc.perform(post("/api/auth/signup")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }
}
