package com.echall.platform.crawling.service;

import static com.echall.platform.message.error.code.CrawlingErrorCode.*;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.echall.platform.message.error.exception.CommonException;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

@Service
public class TranslateService {
	// Instantiates the OkHttpClient.
	OkHttpClient client = new OkHttpClient();

	@Value("${microsoft.key}")
	private String subscriptionKey;

	@Value("${microsoft.endpoint}")
	private String endpoint;

	@Value("${microsoft.location}")
	private String location;

	public String translate(String text, String from, String to) {
		return extractText(Post(text, from, to));
	}

	// This function prettifies the json response.
	private String extractText(String jsonText) {
		JsonParser parser = new JsonParser();
		JsonElement json = parser.parse(jsonText);
		JsonArray translations = json.getAsJsonArray().get(0).getAsJsonObject().getAsJsonArray("translations");
		return translations.get(0).getAsJsonObject().get("text").getAsString();
	}

	// This function performs a POST request.
	private String Post(String text, String from, String to) {
		MediaType mediaType = MediaType.parse("application/json");
		RequestBody body = RequestBody.create(mediaType, "[{\"Text\": \"" + text + "\"}]");
		Request request = new Request.Builder()
			.url(endpoint + "&from=" + from + "&to=" + to)
			.post(body)
			.addHeader("Ocp-Apim-Subscription-Key", subscriptionKey)
			.addHeader("Ocp-Apim-Subscription-Region", location)
			.addHeader("Content-type", "application/json")
			.build();
		try {
			Response response = client.newCall(request).execute();
			return response.body().string();
		} catch (IOException e) {
			throw new CommonException(CRAWLING_TRANSLATE_FAILURE);
		}
	}

}