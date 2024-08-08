package net.yuqiong.oauthserver.oauthserver.controller;

import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
import net.yuqiong.oauthserver.oauthserver.dto.UserInfoDTO;
import net.yuqiong.oauthserver.oauthserver.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * TODO:
 *
 * @Author: MountCloud
 * @Date: 2024年08月07日
 */
@RequestMapping("/api")
@RestController
public class DataController {

    @Autowired
    private UserService userService;

    @GetMapping("/data")
    public String data(){

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("status",0);

        String result = jsonObject.toString();

        return result;
    }

    @GetMapping("/me")
    public String getUserInfo() {
        JsonObject jsonObject = new JsonObject();
        UserInfoDTO currentUserInfo = userService.getCurrentUserInfo();
        jsonObject.addProperty("username", currentUserInfo.getUsername());
        JsonArray authorities = new JsonArray();
        if(currentUserInfo.getAuthorities()!=null && !currentUserInfo.getAuthorities().isEmpty()){
            for (String authority : currentUserInfo.getAuthorities()) {
                authorities.add(authority);
            }
        }
        jsonObject.add("authorities", authorities);
        return jsonObject.toString();
    }

}
