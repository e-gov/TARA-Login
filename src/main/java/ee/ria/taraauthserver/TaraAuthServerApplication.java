package ee.ria.taraauthserver;

// import co.elastic.apm.attach.ElasticApmAttacher;
import ee.ria.taraauthserver.logging.ActiveConfigurationLogger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class TaraAuthServerApplication extends SpringBootServletInitializer {

    public static void main(String[] args) {
        // ElasticApmAttacher.attach();
        SpringApplication.run(TaraAuthServerApplication.class, args);
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        // ElasticApmAttacher.attach();
        builder.application().addListeners(new ActiveConfigurationLogger());
        return builder.sources(TaraAuthServerApplication.class);
    }
}
