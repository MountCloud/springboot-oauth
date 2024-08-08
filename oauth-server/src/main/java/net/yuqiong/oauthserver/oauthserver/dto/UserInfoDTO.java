package net.yuqiong.oauthserver.oauthserver.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * TODO:
 *
 * @Author: MountCloud
 * @Date: 2024年08月08日
 */
@Getter
@Setter
public class UserInfoDTO {

    private String username;

    private List<String> authorities;

}
