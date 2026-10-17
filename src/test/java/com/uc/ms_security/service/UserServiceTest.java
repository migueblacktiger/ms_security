package com.uc.ms_security.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.uc.ms_security.dto.user.CreateUserDTO;
import com.uc.ms_security.dto.user.UpdateUserDTO;
import com.uc.ms_security.dto.user.UserResponseDTO;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.mapper.UserMapper;
import com.uc.ms_security.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserMapper userMapper;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(userRepository, userMapper, passwordEncoder);
    }

    @Test
    void createShouldStoreHashedPassword() {
        CreateUserDTO dto = new CreateUserDTO();
        dto.setName("Juan Pérez");
        dto.setEmail("juan@gmail.com");
        dto.setPassword("12345678");

        User entity = new User();
        entity.setPassword("12345678");

        when(userRepository.existsByEmail("juan@gmail.com")).thenReturn(false);
        when(userMapper.toEntity(dto)).thenReturn(entity);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(userMapper.toResponseDTO(any(User.class)))
                .thenReturn(new UserResponseDTO(1L, "Juan Pérez", "juan@gmail.com"));

        userService.create(dto);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());

        String stored = captor.getValue().getPassword();
        assertNotEquals("12345678", stored);
        assertTrue(passwordEncoder.matches("12345678", stored));
    }

    @Test
    void updateWithoutPasswordShouldKeepExistingHash() {
        User existing = new User();
        existing.setId(1L);
        existing.setPassword("EXISTING_HASH");

        UpdateUserDTO dto = new UpdateUserDTO();
        dto.setName("Juan David");
        dto.setEmail("juan@gmail.com");

        when(userRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(userRepository.existsByEmailAndIdNot("juan@gmail.com", 1L)).thenReturn(false);
        when(userRepository.save(existing)).thenReturn(existing);
        when(userMapper.toResponseDTO(existing))
                .thenReturn(new UserResponseDTO(1L, "Juan David", "juan@gmail.com"));

        userService.update(1L, dto);

        assertEquals("EXISTING_HASH", existing.getPassword());
    }

    @Test
    void updateWithPasswordShouldStoreNewHash() {
        User existing = new User();
        existing.setId(1L);
        existing.setPassword("EXISTING_HASH");

        UpdateUserDTO dto = new UpdateUserDTO();
        dto.setName("Juan David");
        dto.setEmail("juan@gmail.com");
        dto.setPassword("87654321");

        when(userRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(userRepository.existsByEmailAndIdNot("juan@gmail.com", 1L)).thenReturn(false);
        when(userRepository.save(existing)).thenReturn(existing);
        when(userMapper.toResponseDTO(existing))
                .thenReturn(new UserResponseDTO(1L, "Juan David", "juan@gmail.com"));

        userService.update(1L, dto);

        assertNotEquals("87654321", existing.getPassword());
        assertTrue(passwordEncoder.matches("87654321", existing.getPassword()));
    }
}
