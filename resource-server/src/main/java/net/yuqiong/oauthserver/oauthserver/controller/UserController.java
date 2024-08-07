package net.yuqiong.oauthserver.oauthserver.controller;

import com.nimbusds.jose.shaded.gson.JsonObject;
import net.yuqiong.oauthserver.oauthserver.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/info")
    public String getUserInfo() {
        JsonObject jsonObject = new JsonObject();
        Map<String, Object> currentUserInfo = userService.getCurrentUserInfo();
        for(Map.Entry<String, Object> entry : currentUserInfo.entrySet()) {
            jsonObject.addProperty(entry.getKey(), entry.getValue().toString());
        }
        return jsonObject.toString();
    }

}
