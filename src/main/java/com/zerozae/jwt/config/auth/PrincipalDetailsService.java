package com.zerozae.jwt.config.auth;

import com.zerozae.jwt.model.User;
import com.zerozae.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


// http://localhost:8080/login 올때 동작을 함, 그런데 폼 로그인을 사용하지 않기 때문에 기본 주소가 막힘 (동작을 안함) 따라서 PrincipalDetailsService를 때려넣어주는 필터를 따로 만들어야 함
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
}
