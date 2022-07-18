package linz.ian

import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.builder.SpringApplicationBuilder
import org.springframework.context.annotation.Bean
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
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import kotlin.random.Random

fun main() {
    SpringApplicationBuilder(ResourceServiceB::class.java).profiles("b").run()
}

@SpringBootApplication
class ResourceServiceB {

    @Profile("b")
    @Bean
    fun oauth2ClientRestTemplate(
        clientRegistrationRepository: ClientRegistrationRepository,
        authorisedClientManager: OAuth2AuthorizedClientManager
    ): RestTemplate {
        val clientRegistration = clientRegistrationRepository.findByRegistrationId("search-service-b")
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

    private fun createPrincipal(): Authentication = object : Authentication {
        override fun getName(): String = clientRegistration.clientId

        override fun getPrincipal(): Any = this

        override fun isAuthenticated(): Boolean = false

        override fun setAuthenticated(isAuthenticated: Boolean) = throw IllegalArgumentException()

        override fun getAuthorities(): Collection<GrantedAuthority> = emptyList()

        override fun getCredentials(): Any? = null

        override fun getDetails(): Any? = null
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

    @GetMapping("/anon")
    fun anonymousHello() = "Hi"
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

@Profile("b")
@EnableWebSecurity
class OAuth2SecurityConfigB : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http {
            authorizeRequests {
                authorize("/api/hello", authenticated)
                // this only allows anoymous and replies 403 if authenticated
                authorize("/api/anon", anonymous)
                // to allow anonymous and authenticated then use permitAll
                // authorize("/api/anon", permitAll)
            }
            oauth2ResourceServer {
                jwt {
                    jwtAuthenticationConverter = JwtBearerTokenAuthenticationConverter()
                }
            }
        }
    }
}

