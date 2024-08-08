package net.yuqiong.oauthserver.oauthserver.controller;

import com.nimbusds.jose.shaded.gson.JsonObject;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * TODO:
 *
 * @Author: MountCloud
 * @Date: 2024年08月08日
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/info")
    public String data(){

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("status",0);

        String result = jsonObject.toString();

        return result;
    }

}
