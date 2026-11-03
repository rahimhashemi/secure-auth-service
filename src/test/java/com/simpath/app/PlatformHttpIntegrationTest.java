package com.simpath.app;

import com.simpath.app.auth.dto.RegisterRequest;
import com.simpath.app.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.test.annotation.DirtiesContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

// Exercise the embedded servlet container and actual HTTP/JSON conversion, not only MockMvc.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt.secret=test-only-key-with-at-least-thirty-two-characters",
        "app.refresh-token.pepper=test-only-pepper",
        "spring.datasource.username=test", "spring.datasource.password=test",
        "app.token-cleanup.cron=-", "spring.jpa.show-sql=false",
        "springdoc.api-docs.enabled=true", "springdoc.swagger-ui.enabled=true"
})
@Import(AuthIntegrationTest.Containers.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class PlatformHttpIntegrationTest {
    @Autowired Environment environment;
    @Autowired JsonMapper json;
    @Autowired AuthService auth;
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NORMAL).build();

    private URI url(String path) {
        return URI.create("http://127.0.0.1:" + environment.getRequiredProperty("local.server.port") + path);
    }
    private HttpResponse<String> get(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(url(path)).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
    private HttpResponse<String> post(String path, Map<String, String> body) throws Exception {
        return client.send(HttpRequest.newBuilder(url(path)).timeout(Duration.ofSeconds(10))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body))).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test void openApiIsGeneratedWhenExplicitlyEnabled() throws Exception {
        HttpResponse<String> response = get("/v3/api-docs");
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode document = json.readTree(response.body());
        assertThat(document.path("openapi").asText()).startsWith("3.");
        assertThat(document.path("paths").has("/auth/login")).isTrue();
        assertThat(document.path("paths").has("/auth/refresh")).isTrue();
    }

    @Test void swaggerUiResourcesAreServedWhenExplicitlyEnabled() throws Exception {
        HttpResponse<String> response = get("/swagger-ui/index.html");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("Swagger UI");
    }

    @Test void loginProtectedEndpointRefreshAndLogoutPreserveTheirHttpContract() throws Exception {
        String email = "platform-http@example.com";
        String password = "Correct-Horse-123!";
        auth.register(new RegisterRequest(email, password));
        HttpResponse<String> login = post("/auth/login", Map.of("email", email, "password", password));
        assertThat(login.statusCode()).isEqualTo(200);
        JsonNode session = json.readTree(login.body());
        String access = session.path("accessToken").asText();
        String refresh = session.path("refreshToken").asText();
        assertThat(access).isNotBlank();
        assertThat(refresh).isNotBlank();
        assertThat(session.path("accessExpiresInSeconds").asLong()).isPositive();
        assertThat(session.path("refreshExpiresInSeconds").asLong()).isPositive();
        HttpResponse<String> me = client.send(HttpRequest.newBuilder(url("/me"))
                .timeout(Duration.ofSeconds(10)).header("Authorization", "Bearer " + access).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(me.statusCode()).isEqualTo(200);
        assertThat(json.readTree(me.body()).path("email").asText()).isEqualTo(email);

        HttpResponse<String> rotated = post("/auth/refresh", Map.of("refreshToken", refresh));
        assertThat(rotated.statusCode()).isEqualTo(200);
        String successor = json.readTree(rotated.body()).path("refreshToken").asText();
        assertThat(successor).isNotBlank().isNotEqualTo(refresh);
        assertThat(post("/auth/logout", Map.of("refreshToken", successor)).statusCode()).isEqualTo(200);
        HttpResponse<String> rejected = post("/auth/refresh", Map.of("refreshToken", successor));
        assertThat(rejected.statusCode()).isEqualTo(401);
        JsonNode error = json.readTree(rejected.body());
        assertThat(error.path("code").asText()).isEqualTo("INVALID_REFRESH_TOKEN");
        assertThat(Instant.parse(error.path("timestamp").asText())).isNotNull();
        assertThat(error.path("path").asText()).isEqualTo("/auth/refresh");
    }
}
