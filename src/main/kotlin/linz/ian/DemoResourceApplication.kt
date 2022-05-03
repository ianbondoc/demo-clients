package linz.ian

import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.http.HttpRequest
import org.springframework.http.client.ClientHttpRequestExecution
import org.springframework.http.client.ClientHttpRequestInterceptor
import org.springframework.http.client.ClientHttpResponse
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.client.*
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import kotlin.random.Random

@SpringBootApplication
class DemoResourceApplication

fun main(args: Array<String>) {
    runApplication<DemoResourceApplication>(*args)
}

data class Request(val sender: String)
data class Response(val message: String)

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

@RestController
@RequestMapping("/api")
@Profile("b")
class ServiceB {
    @PostMapping("/hello")
    fun sayHello(@RequestBody request: Request): Response {
        val context = SecurityContextHolder.getContext()
        val token = context.authentication
        System.err.println(token)
        val somRandomNumber = Random.nextInt(101, 200)
        return Response("hello ${request.sender}! [$somRandomNumber]")
    }
}

// this is for testing service account (we could look at O
@Profile("b")
@Component
class DaemonB(val restTemplate: RestTemplate) : ApplicationRunner {
    override fun run(args: ApplicationArguments?) {
        val aResponse = runCatching {
            checkNotNull(
                restTemplate.postForObject(
                    "http://localhost:8081/api/hello-internal",
                    Request("service-b"),
                    Response::class.java
                )
            )
        }.getOrElse {
            it.printStackTrace()
            Response("Encountered ${it::class.qualifiedName} : ${it.message}")
        }
        System.err.println("Result: $aResponse")
    }
}

@EnableWebSecurity
class OAuth2LoginSecurityConfig : WebSecurityConfigurerAdapter() {

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
            // oauth2Client {
            // }
        }
    }
}

@Configuration
class SecurityConfiguration {

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

    @Profile("b")
    @Bean
    fun oauth2ClientRestTemplate(
        clientRegistrationRepository: ClientRegistrationRepository,
        authorisedClientManager: OAuth2AuthorizedClientManager
    ): RestTemplate {
        val clientRegistration = clientRegistrationRepository.findByRegistrationId("search-service-a")
        return RestTemplate().apply {
            interceptors.add(OAuthClientCredentialsRestTemplateInterceptor(authorisedClientManager, clientRegistration))
        }
    }

    @Profile("b")
    @Bean
    fun authorisedClientManager(
        clientRegistrationRepository: ClientRegistrationRepository,
        oAuth2AuthorizedClientService: OAuth2AuthorizedClientService
    ): OAuth2AuthorizedClientManager =
        AuthorizedClientServiceOAuth2AuthorizedClientManager(
            clientRegistrationRepository,
            oAuth2AuthorizedClientService
        ).apply {
            setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder().clientCredentials().build())
        }
}

class OAuthClientCredentialsRestTemplateInterceptor(
    private val manager: OAuth2AuthorizedClientManager,
    private val clientRegistration: ClientRegistration
) : ClientHttpRequestInterceptor {
    override fun intercept(
        request: HttpRequest,
        body: ByteArray,
        execution: ClientHttpRequestExecution
    ): ClientHttpResponse {

        val authoriseRequest = OAuth2AuthorizeRequest
            .withClientRegistrationId(clientRegistration.registrationId)
            .principal(createPrincipal())
            .build()

        val client = checkNotNull(manager.authorize(authoriseRequest))

        request.headers["Authorization"] = "Bearer ${client.accessToken.tokenValue}"

        return execution.execute(request, body)
    }

    private fun createPrincipal(): Authentication = object: Authentication {
        override fun getName(): String = clientRegistration.clientId

        override fun getPrincipal(): Any = this

        override fun isAuthenticated(): Boolean = false

        override fun setAuthenticated(isAuthenticated: Boolean) = throw IllegalArgumentException()

        override fun getAuthorities(): Collection<GrantedAuthority> = emptyList()

        override fun getCredentials(): Any? = null

        override fun getDetails(): Any? = null
    }
}