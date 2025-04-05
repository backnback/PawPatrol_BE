package com.patrol;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public class ApiTest {

  @LocalServerPort
  private int port;

  @Autowired
  private TestRestTemplate restTemplate;

  @Test
  void repeatApiCall() {
    String loginUrl = "http://localhost:" + port + "/api/v2/auth/login";

    Map<String, String> loginRequest = new HashMap<>();
    loginRequest.put("email", "center2@test.com");
    loginRequest.put("password", "1234");
    loginRequest.put("token", "");

    HttpHeaders loginHeaders = new HttpHeaders();
    loginHeaders.setContentType(MediaType.APPLICATION_JSON);

    HttpEntity<Map<String, String>> loginEntity = new HttpEntity<>(loginRequest, loginHeaders);
    ResponseEntity<String> loginResponse = restTemplate.exchange(loginUrl, HttpMethod.POST, loginEntity, String.class);

    List<String> cookies = loginResponse.getHeaders().get("Set-Cookie");

    HttpHeaders headers = new HttpHeaders();
    if (cookies != null) {
      headers.put(HttpHeaders.COOKIE, cookies);
    }
    HttpEntity<Void> entity = new HttpEntity<>(headers);

    String baseUrl = "http://localhost:" + port + "/api/v1/protections/my-cases";

    for (int i = 0; i < 10; i++) {
      ResponseEntity<String> response = restTemplate.exchange(baseUrl, HttpMethod.GET, entity, String.class);
      System.out.println("Status: " + response.getStatusCode());
      System.out.println("Body: " + response.getBody());
      assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }
  }

}
