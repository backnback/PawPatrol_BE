package com.patrol.global.webMvc;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class ApiLoggingInterceptor implements HandlerInterceptor {

  private static final Logger logger = LoggerFactory.getLogger("API_LOGGER");

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
    String method = request.getMethod();
    String uri = request.getRequestURI();
    String queryString = request.getQueryString();

    if (queryString != null) {
      uri += "?" + queryString;
    }

    logger.info("\n\u001B[32m========== API 호출 시작: " + method + " " + uri + " ==========\u001B[0m");
    request.setAttribute("startTime", System.currentTimeMillis());
    return true;
  }

  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
    Long startTime = (Long) request.getAttribute("startTime");
    if (startTime != null) {
      long executionTime = System.currentTimeMillis() - startTime;
      String method = request.getMethod();
      String uri = request.getRequestURI();

      logger.info("\u001B[32m========== API 호출 완료: " + method + " " + uri +
          " | 실행시간: " + executionTime + "ms | 상태코드: " + response.getStatus() + " ==========\u001B[0m\n");
    }
  }
}
