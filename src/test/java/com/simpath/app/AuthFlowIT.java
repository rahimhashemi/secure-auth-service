package com.simpath.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers
//@TestConstructor(autowireMode = TestConstructor.AutowireMode.ALL)
@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowIT {

  @Container
  static PostgreSQLContainer<?> postgreSQLContainer = new PostgreSQLContainer<>("postgres:16")
    .withDatabaseName("authdb")
    .withUsername("auth")
    .withPassword("authpass");

  @DynamicPropertySource
  static void props(DynamicPropertyRegistry r) {
    r.add("spring.datasource.url", postgreSQLContainer::getJdbcUrl);
    r.add("spring.datasource.username", postgreSQLContainer::getUsername);
    r.add("spring.datasource.password", postgreSQLContainer::getPassword);
    r.add("spring.jpa.hibernate.ddl-auto", () -> "update");
    r.add("app.jwt.secret", () -> "change-me-change-me-change-me-change-me");
    r.add("app.refresh-token.pepper", () -> "pepper-change-me");
  }

  @Autowired MockMvc mvc;
  @Autowired ObjectMapper om;

  record Reg(String email, String password) {}
  record Login(String email, String password) {}
  record Refresh(String refreshToken) {}

  static class Tokens {
    public String accessToken;
    public long accessExpiresInSeconds;
    public String refreshToken;
    public long refreshExpiresInSeconds;
  }

  @Test
  void refreshRotation_and_reuseDetection() throws Exception {
    // register
    mvc.perform(post("/auth/register")
        .contentType("application/json")
        .content(om.writeValueAsString(new Reg("a@b.com", "Passw0rd!"))))
      .andExpect(status().isOk());

    // login
    var loginRes = mvc.perform(post("/auth/login")
        .contentType("application/json")
        .header("User-Agent", "test")
        .content(om.writeValueAsString(new Login("a@b.com", "Passw0rd!"))))
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    Tokens t1 = om.readValue(loginRes, Tokens.class);

    // refresh -> should rotate (new refresh token)
    var refreshRes = mvc.perform(post("/auth/refresh")
        .contentType("application/json")
        .header("User-Agent", "test")
        .content(om.writeValueAsString(new Refresh(t1.refreshToken))))
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    Tokens t2 = om.readValue(refreshRes, Tokens.class);

    // old refresh token reuse => should 401 (and revokeAll behind the scenes)
    mvc.perform(post("/auth/refresh")
        .contentType("application/json")
        .header("User-Agent", "test")
        .content(om.writeValueAsString(new Refresh(t1.refreshToken))))
      .andExpect(status().isUnauthorized());

    // new refresh should now be revoked because revokeAll happened (depending on your implementation)
    // اگر revokeAll در reuse فعال است:
    mvc.perform(post("/auth/refresh")
        .contentType("application/json")
        .header("User-Agent", "test")
        .content(om.writeValueAsString(new Refresh(t2.refreshToken))))
      .andExpect(status().isUnauthorized());
  }

  @Test
  void accessToken_allows_me_endpoint() throws Exception {
    mvc.perform(post("/auth/register")
        .contentType("application/json")
        .content(om.writeValueAsString(new Reg("x@y.com", "Passw0rd!"))))
      .andExpect(status().isOk());

    var loginRes = mvc.perform(post("/auth/login")
        .contentType("application/json")
        .header("User-Agent", "test")
        .content(om.writeValueAsString(new Login("x@y.com", "Passw0rd!"))))
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    Tokens t = om.readValue(loginRes, Tokens.class);

    mvc.perform(get("/me")
        .header("Authorization", "Bearer " + t.accessToken))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.email").value("x@y.com"));
  }
}
