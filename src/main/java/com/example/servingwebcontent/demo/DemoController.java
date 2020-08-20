package com.example.servingwebcontent.demo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class DemoController {

    @RequestMapping(value = "/")
    public String index() {
        return "index";
    }

    @GetMapping("/demo")
    public String demo(@RequestParam(name="name",required = false,
    defaultValue = "World!!") final String name, final Model model) {
        model.addAttribute("name", name);
        return "demo";
    }
    
}