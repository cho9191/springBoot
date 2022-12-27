package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        System.out.println("test filterChain!!");

        http
                .csrf().disable()
                . authorizeRequests()
                //antMatchers 설정한 리소스의 접근을 인증절차 없이 허용
                .antMatchers("/login**", "/web-resources/**", "/actuator/**").permitAll()
                //인증 후 ADMIN 레벨의 권한을 가진 사용자만 접근을 허용한다는
                .antMatchers("/admin/**").hasAnyRole("ADMIN")
                .antMatchers("/order/**").hasAnyRole("USER")

                //그외 나머지 리소스들은 무조건 인증을 완료해야 접근이 가능
                .anyRequest().authenticated()
            .and()
                .formLogin()
                .loginPage("/login.html")
                .usernameParameter("id")
                .passwordParameter("pwd")
                .loginProcessingUrl("/ttt")
                .defaultSuccessUrl("/index.html")

                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException, IOException {
                        System.out.println("로그인 성공 authentication : " + authentication.getName());
                        response.sendRedirect("/index.html");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("여기 exception : " + exception.getMessage());
                        response.sendRedirect("/login.html");
                    }
                })
        ;

/*
        http.formLogin()
                //사용자가 따로 만든 로그인 페이지를 사용하려고 할때 설정
                .loginPage("/login.html")
                //로그인 즉 인증 처리를 하는 URL을 설정. “/login-process” 가 호출되면 인증처리를 수행하는 필터가 호출
                .loginProcessingUrl("/login-process")
                //정상적으로 인증성공 했을 경우 이동하는 페이지를 설정
                .defaultSuccessUrl("/main")
                //정상적인증 성공 후 별도의 처리가 필요한경우 커스텀 핸들러를 생성하여 등록
                //.successHandler(new CustomAuthenticationSuccessHandler("/main"))
                //인증이 실패 했을 경우 이동하는 페이지를 설정
                .failureUrl("login-fail")
                //인증 실패 후 별도의 처리가 필요한경우 커스텀 핸들러를 생성하여 등록
                //.failureHandler(new CustomAuthenticationFailureHandler("/login-fail")
*/



        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        System.out.println("test webSecurityCustomizer!!");
        return (web) -> web.ignoring().antMatchers("/images/**", "/js/**", "/webjars/**");
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {

        System.out.println("test userDetailsService!!");

        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

        manager.createUser(User.withUsername("admin").password(encoder.encode("1111")).roles("ADMIN", "USER", "SYS").build());
        manager.createUser(User.withUsername("user").password(encoder.encode("1111")).roles("USER").build());
        manager.createUser(User.withUsername("sys").password(encoder.encode("1111")).roles("SYS", "USER").build());

        return manager;
    }
/*
    @Bean
    public UserDetailsService userDetailsService() {

        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return null;
            }
        };
    }*/

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}