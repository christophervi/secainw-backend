package edu.sjsu.cmpe.secainw.config;

import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.deepseek.DeepSeekChatModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class AiConfig {
	
	//@Primary
	@Bean
	public ChatClient openAiChatClient(OpenAiChatModel chatModel) {
		return ChatClient.builder(chatModel).build();
	}

	@Bean
	public ChatClient anthropicChatClient(AnthropicChatModel chatModel) {
		return ChatClient.builder(chatModel).build();
	}

	@Primary
	@Bean
	public ChatClient deepSeekChatClient(DeepSeekChatModel chatModel) {
		return ChatClient.builder(chatModel).build();
	}
}
