package com.dkaedv.glghproxy.controller;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.dkaedv.glghproxy.gitlabclient.OAuthClient;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@Controller
@RequestMapping("/login/oauth")
public class LoginController {
	private static final Log LOG = LogFactory.getLog(ReposController.class);

	@Value("${gitlabUrl}")
	private String gitlabUrl;

	@Autowired
	private OAuthClient oauthClient;

	private String redirectUri;

	/**
	 * Step 1 - OAuth request from client application (e.g. JIRA)
	 * @throws MalformedURLException
	 */
	@RequestMapping("/authorize")
	public String authorize(
			@RequestParam String scope,
			@RequestParam String client_id,
			@RequestParam String redirect_uri,
			HttpServletRequest request, HttpServletResponse response) throws UnsupportedEncodingException, MalformedURLException {

		// Save redirect uri
		response.addCookie(new Cookie("redirect_url", redirect_uri));

		String callbackUrl = buildCallbackUrl(request);

		return "redirect:" + gitlabUrl + "/oauth/authorize?client_id=" + client_id + "&response_type=code&redirect_uri=" + callbackUrl;
	}

	private String buildCallbackUrl(HttpServletRequest request) throws MalformedURLException {
		ServletUriComponentsBuilder builder = ServletUriComponentsBuilder.fromCurrentRequest();

		builder.replacePath("/login/oauth/authorize_callback");
		builder.replaceQuery(null);
		builder.port(null);

		return builder.build().toUri().toString();
	}

	private String extractCookie(HttpServletRequest req, String cookieName) {
		for (Cookie c : req.getCookies()) {
			if (c.getName().equals(cookieName))
				return c.getValue();
		}
		return null;
	}

	@RequestMapping("/authorize_callback")
	public String gitlabCallback(
			@RequestParam String code,
			HttpServletRequest request
			) {

		String redirectUrl = extractCookie(request, "redirect_url");
		String answer;

		if(redirectUrl != null) {
			answer = "redirect:" + redirectUrl + "&code=" + code;
		} else {
			answer = "redirect:" + gitlabUrl;
		}

		return answer;
	}


	/**
	 * Step 3 - Client application exchanges code for an access token.
	 */
	@RequestMapping(value = "/access_token", method = RequestMethod.POST)
	@ResponseBody
	public String accessToken(
			@RequestParam String client_id,
			@RequestParam String client_secret,
			@RequestParam String code,
			HttpServletRequest request
			) throws MalformedURLException {

		return oauthClient.requestAccessToken(client_id, client_secret, code, buildCallbackUrl(request)).toString();
	}
}
