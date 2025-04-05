package com.patrol.global.webMvc;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

@Component
public class LogCleaner {

  @EventListener(ApplicationReadyEvent.class)
  public void clearHibernateLog() {
    try {
      Files.write(Paths.get("logs/hibernate.log"), new byte[0], StandardOpenOption.TRUNCATE_EXISTING);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}
