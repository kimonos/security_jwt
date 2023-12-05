package com.example.security_jwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component //將其視為spring boot泛用組件
@RequiredArgsConstructor //生成一個包含 “特定參數” 的 constructor，特定參數指的是那些有加上 final 修飾詞的變量們
//繼承OncePerRequestFilter，是確保每一次的請求只會經過一次的filter，不會重複執行
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;//引入商業邏輯
    private final UserDetailsService userDetailsService; //對於Security中的使用者的商業邏輯

    @Override
    protected void doFilterInternal(//確保單一請求的執行緒只會被呼叫一次
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain //FilterChain為各個Filter的集合，其中會包含各個不同的Filter
            //@NonNull表示對應值不能為空值
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authentication");//設定一個字串變數authHeader來儲存"Authenication"標頭的值
        final String jwt; //設定一個字串變數jwt
        final String username; //設定一個字串變數username
        if(authHeader == null || !authHeader.startsWith("Bearer ")){ //當authHeader是空值或者authHeader不是開始於"Bearer "時
            filterChain.doFilter(request,response);//直接進行下一個Filter
            return; //終止當前的filter
        }
        jwt = authHeader.substring(7);//將jwt值設為"Bearer "後方的token
        username = jwtService.extractUsername(jwt);
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){//確保username不是空值跟SecurityContextHolder還沒有認證
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            if(jwtService.isTokenValid(jwt, userDetails)){//確認token是否有效
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,//使用者姓名
                        null,
                        userDetails.getAuthorities()//使用者權限資訊
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)//透過HTTP請求獲取特定的相關訊息
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);//在SecurityContextHolder設置使用者相關訊息
            }
        }
    }
}
