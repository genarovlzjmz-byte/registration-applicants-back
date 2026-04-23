package mx.edu.chapingo.siani;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class SianiApplication {
    public static void main(String[] args) {
        SpringApplication.run(SianiApplication.class, args);
    }
}
