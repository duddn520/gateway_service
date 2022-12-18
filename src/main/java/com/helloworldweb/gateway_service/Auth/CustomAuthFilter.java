package com.helloworldweb.gateway_service.Auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class CustomAuthFilter extends AbstractGatewayFilterFactory {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            MultiValueMap<String, HttpCookie> cookies = request.getCookies();
            List<HttpCookie> auth = cookies.get("Auth");
            HttpCookie httpCookie = auth.get(0);
            String token = httpCookie.getValue();

            if(!jwtTokenProvider.validateTokenWithDate(token)){
                return handleUnAuthorized(exchange);
            }

            return chain.filter(exchange);
        };
    }

    private Mono<Void> handleUnAuthorized(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();

        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }
}
