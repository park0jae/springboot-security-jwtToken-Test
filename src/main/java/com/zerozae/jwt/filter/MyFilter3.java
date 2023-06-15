package com.zerozae.jwt.filter;


import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("필터3");

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;



        // 자 이제 이 토큰을 만드는 작업을 수행할거임 , 언제 ? (ID, PW가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답 해준다.)
        // 요청할 때마다 Header에 Authorization에 value 값으로 토큰을 가지고 오겠죠 ? 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨 (RSA, HS256)
        if(req.getMethod().equals("POST")){
            String authorization = req.getHeader("Authorization");
            log.info("Authorization = {}", authorization);
            log.info("필터1");

            // zerozae가 들어오면 인증이 된 사람이기 때문에 chain.doFilter 수행, 아니면 인증되지 않았기 떄문에 인증안됨을 출력
            // 이 필터는 시큐리티가 들어오기 전에 동작해야 함, 그래서 SecurityConfig에 addFilterBefore로 등록해놓음
            if(authorization.equals("zerozae")){
                chain.doFilter(req,res);
            }else {
                PrintWriter writer = res.getWriter();
                writer.println("인증 안됨");
            }
        }
    }
}
