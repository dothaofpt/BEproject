package org.example.api_gateway.configuration;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    @Value("${jwt.secret}")
    private String secretKey;

    public JwtAuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            if (path.contains("/auth/")) {
                return chain.filter(exchange);  // Bỏ qua các yêu cầu tới "/auth/"
            }

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return this.onError(exchange, "Missing authorization header", 401);
            }

            String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            String token = authorizationHeader.substring(7);  // Loại bỏ "Bearer "

            try {
                Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
                String username = claims.getSubject();

                // Thêm thông tin từ token vào request headers
                exchange.getRequest().mutate()
                        .header("username", username)
                        .header("roles", String.join(",", claims.get("roles", List.class)))
                        .build();
            } catch (SignatureException e) {
                return this.onError(exchange, "Invalid JWT signature", 401);
            } catch (Exception e) {
                return this.onError(exchange, "JWT token parsing error", 401);
            }

            return chain.filter(exchange);  // Tiếp tục xử lý yêu cầu
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, int httpStatus) {
        exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.valueOf(httpStatus));
        return exchange.getResponse().setComplete();
    }

    public static class Config {
    }
}
