package com.velox.adfsApi.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.Attribute;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {
	@RequestMapping("/")
	public String index() {
		return "index";
	}

	@GetMapping(value="/mainControl")
	ResponseEntity<?> getTicketStatus() {

		System.out.println("In maincontrol");
		
		return ResponseEntity.status(HttpStatus.ACCEPTED).body("success in mainControl");
	}
	
	@GetMapping(value = "/auth")
	public String handleSamlAuth(ExpiringUsernameAuthenticationToken userToken, HttpServletRequest request,
			HttpServletResponse response) {
//		PrintWriter out = null;
		
		Authentication auth = null;
		try {
			SecurityContext context = SecurityContextHolder.getContext();
			auth = context.getAuthentication();
			
//			out = response.getWriter();
		} catch (Exception e) {
			System.out.println("Exception in Authentication : "+ e);
			e.printStackTrace();
		}
		if (auth != null) {
			return "redirect:/home";
		} else {
			return "/";
		}
	}

	@GetMapping("/home")
	public String home(Model model, ExpiringUsernameAuthenticationToken userToken) {
		SAMLCredential credential = (SAMLCredential) userToken.getCredentials();
		List<Attribute> attributes = credential.getAttributes();
		System.out.println("userToken.getName() : " + userToken.getName());
		System.out.println("attributes: " + attributes);
//		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//		model.addAttribute("username", authentication.getPrincipal());
//		JSONObject resultJson = new JSONObject();
		for (Attribute data : attributes) {
			System.out.println(data.getName() + " == " + credential.getAttributeAsString(data.getName()));
//			resultJson.put(data.getName(), credential.getAttributeAsString(data.getName()));
			model.addAttribute(data.getName(), credential.getAttributeAsString(data.getName()));
		}
		model.addAttribute("username", userToken.getName());
		return "home";
//		return ResponseEntity.ok().body(resultJson);
//		return resultJson;
	}
}
