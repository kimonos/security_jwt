package com.example.security_jwt.User;

//import jakarta.persistence.Entity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

@Data //提供該類別@Getter跟@Setter的方法，可以減少程式碼(incloud:@ToString,@EqualsAndHashCode,@RequiredArgsConstructor)
@NoArgsConstructor //生成一個沒有參數的constructor
@AllArgsConstructor //生成一個包含所有參數的 constructor
@Builder //建構者模式
@Entity //會被標記成持久化實體(JPA)，此類別會對應(映射)到資料庫相對應的表格
@Table(name = "users")  //正常下JPA會默認與實體類別相同的表格，也可以自行指定


// UserDetail為spring security中的一個介面，提供了用戶的基本資訊，如用戶名、密碼、角色、帳號是否過期、帳號是否被鎖定、帳號是否被禁用等等方法
public class User implements UserDetails , Serializable {

    @Id//設定實體類別的主鍵(Primary key)
    @GeneratedValue(strategy = GenerationType.IDENTITY) //定義如何生成主鍵的值，這裡使用自動增長
    private int id;

    private String username;

    private String name;

    private String email;

    private String password;

    @Enumerated(EnumType.STRING)//將枚舉類型映射到資料表的相對應欄位，EnumType是將枚舉類型中以字串方式存入
    private Role role; //使用者權限

    @Override
    public String getUsername() {
        return username;
    } //返回用戶名

    @Override
    public String getPassword() {
        return password;
    } //返回用戶的加密後的密碼。

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { //方法返回一個表示用戶所擁有的權限（角色）的集合
        //List.of為List方法，返回一個不可變的集合(Immutable Collections)
        //SimpleGrantedAuthority實作GrantedAuthority，將role.name中的角色擁有權限
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public boolean isAccountNonExpired() { //表示用戶的帳號是否未過期。
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { //表示用戶的帳號是否未被鎖定
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { //表示用戶的認證（密碼）是否未過期
        return true;
    }

    @Override
    public boolean isEnabled() { //用戶是否啟用（非禁用）
        return true;
    }
}
