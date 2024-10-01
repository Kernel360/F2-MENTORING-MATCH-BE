package com.echall.platform.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

import org.springframework.util.SerializationUtils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CookieUtil {
	// TODO: https 연결하고 검토 필요
	public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
		Cookie cookie = new Cookie(name, value);
		cookie.setMaxAge(maxAge);
		cookie.setPath("/");
		cookie.setHttpOnly(false);
		cookie.setSecure(false);		
    cookie.setAttribute("SameSite", "None");


		// cookie.setHttpOnly(true);
		// cookie.setSecure(true);
		// cookie.setDomain("localhost");

		response.addCookie(cookie);
	}

	public static void removeCookie(HttpServletRequest request, HttpServletResponse response, String name) {
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(name)) {
					cookie.setValue("");
					cookie.setMaxAge(0);
					cookie.setPath("/");
					// cookie.setHttpOnly(true);
					// cookie.setSecure(true);

					response.addCookie(cookie);
				}
			}
		}
	}

	public static String serialize(Object obj) {
		return Base64.getUrlEncoder()
			.encodeToString(SerializationUtils.serialize(obj));
	}

	public static <T> T deserialize(Cookie cookie, Class<T> cls) {
		byte[] decodedBytes = Base64.getUrlDecoder().decode(cookie.getValue());

		try (
			 ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(decodedBytes))
		) {
			return cls.cast(objectInputStream.readObject());
		} catch (IOException | ClassNotFoundException e) {
			throw new IllegalArgumentException("Failed to deserialize object", e);
		}
	}

}
