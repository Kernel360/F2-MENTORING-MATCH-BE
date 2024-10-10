package com.echall.platform.question.domain.entity;

import org.springframework.data.mongodb.core.mapping.Document;

import com.echall.platform.question.repository.QuestionRepository;
import com.echall.platform.util.MongoBaseDocument;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Document(collection = "question")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class QuestionDocument extends MongoBaseDocument {

	private String question;
	private String answer;

	@Builder
	public QuestionDocument(String question, String answer) {
		this.question = question;
		this.answer = answer;
	}

	public static String saveToMongo(QuestionRepository questionRepository, String question, String answer) {
		QuestionDocument questionDocument = QuestionDocument.builder()
			.question(question)
			.answer(answer)
			.build();
		questionRepository.save(questionDocument);

		return questionDocument.getId().toString();
	}
}
