package com.example.security_jwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service //標示為服務層組件
public class JwtService {
    private static final String SECRET_KEY="2f911e35fe0d55abae8dd173c902f1e9cbb2804b3866e6fab86f100a1ea7da14"; ///設定私鑰

    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);//獲取聲明中的sub
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }
    public String generateToken( //產生token
            Map<String, Object> extraClaim, //額外資訊的簽名格式
            UserDetails userDetails //顧客資訊
    ){
        return Jwts
                .builder() //創建JWT建構器
                .setClaims(extraClaim) //將而外資訊放入簽章
                .setSubject(userDetails.getUsername()) //將使用者名稱設為JWT主題的聲明
                .setIssuedAt(new Date(System.currentTimeMillis())) //設置JWT的發行時間為當前時間
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24)) //設置JWT的過期時間為發行時間的一天後
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) //使用指定的金鑰和簽名演算法簽署JWT
                .compact();//壓縮並生成JWT Token
    }
    public boolean isTokenValid(String token, UserDetails userDetails){ //確認token是否有效
        final String username = extractUsername(token); //設定字串變數username存放JWT token中的sub
        return (username.equals(userDetails.getUsername()))&& !isTokenExpired(token);//確保姓名與token沒有過期
    }

    private boolean isTokenExpired(String token) { //確認token是否過期
        return extractExpiration(token).before(new Date());
    }
    private Date extractExpiration(String token) { //抓取token中的過期時間
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> ClaimResolver){//從聲明中提取特定的聲明
        final Claims claims = extractAllClaims(token);
        return ClaimResolver.apply(claims);
    }
    private Claims extractAllClaims(String token){ //儲存聲明的物件
        return Jwts //在json物件中傳遞jwt簽章
                .parserBuilder() //創建JwtParserBuilder 物件，該物件用於解析和驗證
                .setSigningKey(getSignInKey()) // 設定了簽名金鑰（signing key），用於驗證 JWT 的簽章
                .build() //構建了 JwtParser 物件，用於解析 JWT
                .parseClaimsJws(token) //解析傳入的 JWT 字串，並返回一個 Jws 物件，它包含了原始 JWT 的標頭、有效載荷以及簽章
                .getBody();// 取得 JWT 的有效載荷（payload），即 JWT 中包含的所有聲明
    }

    private Key getSignInKey() { //取得JWT密鑰
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY); //定義一個bytes陣列keyBytes接收一個BASE64編碼的字串並將其解碼成原始資料
        return Keys.hmacShaKeyFor(keyBytes); //回傳HMAC密鑰

    }
}
