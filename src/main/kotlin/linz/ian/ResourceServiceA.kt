package linz.ian

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.builder.SpringApplicationBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Profile
import org.springframework.http.client.ClientHttpRequestInterceptor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import kotlin.random.Random

fun main() {
    SpringApplicationBuilder(ResourceServiceA::class.java).profiles("a").run()
}

@SpringBootApplication
class ResourceServiceA {
    @Profile("a")
    @Bean
    fun oauth2UserRestTemplate() = RestTemplate().apply {
        interceptors.add(ClientHttpRequestInterceptor { request, body, execution ->
            val token =
                (SecurityContextHolder.getContext().authentication as BearerTokenAuthentication).token.tokenValue
            request.headers["Authorization"] = "Bearer $token"
            execution.execute(request, body)
        })
    }
}

@RestController
@RequestMapping("/api")
@Profile("a")
class ServiceA(val restTemplate: RestTemplate) {
    @PostMapping("/hello")
    fun sayHello(@RequestBody request: Request): Response {
        val context = SecurityContextHolder.getContext()
        val token = context.authentication
        System.err.println(token)
        val bResponse = runCatching {
            checkNotNull(
                restTemplate.postForObject(
                    "http://localhost:8082/api/hello",
                    Request("service-a"),
                    Response::class.java
                )
            )
        }.getOrElse { exception ->
            exception.printStackTrace()
            Response("Unavailable")
        }
        val somRandomNumber = Random.nextInt(0, 100)
        return Response("hello ${request.sender}! [$somRandomNumber] and also ${bResponse.message} from service-b")
    }

    @PostMapping("/hello-internal")
    fun sayHelloToFellowService(@RequestBody request: Request): Response {
        val somRandomNumber = Random.nextInt(0, 100)
        return Response("hello ${request.sender} service! [$somRandomNumber]")
    }
}

@Profile("a")
@EnableWebSecurity
class OAuth2SecurityConfigA : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http {
            csrf {
                csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse()
            }
            cors {
                configurationSource = UrlBasedCorsConfigurationSource().apply {
                    // only public endpoints require cors but it doesn't matter as the browser is the one
                    // blocking the response, a rest client like RestTemplate won't care about cors headers returned by
                    // the endpoint
                    registerCorsConfiguration("/api/hello", CorsConfiguration().apply {
                        allowedOrigins = listOf("http://localhost:3000")
                        allowedMethods = listOf("GET", "POST")
                        allowedHeaders = listOf("*")
                        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
                        allowCredentials = true
                    })
                }
            }
            authorizeRequests {
                authorize(anyRequest, authenticated)
            }
            oauth2ResourceServer {
                jwt {
                    jwtAuthenticationConverter = JwtBearerTokenAuthenticationConverter()
                }
            }
        }
    }
}