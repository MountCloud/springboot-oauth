package net.yuqiong.oauthserver.oauthserver.controller;

import com.nimbusds.jose.shaded.gson.JsonObject;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @GetMapping("/info")
    public String data(){

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("status",0);

        String result = jsonObject.toString();

        return result;
    }

}
