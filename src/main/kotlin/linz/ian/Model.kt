package linz.ian

data class Request(val sender: String)
data class Response(val message: String)

// @Component
// class JwtToGrantedAuthoritiesMapper(private val restTemplate: RestTemplate) : Converter<Jwt, AbstractAuthenticationToken> {
//     val delegate = NimbusReactiveOpaqueTokenIntrospector("http://localhost:8080/realms/landonline", "search-service-a", "pp8k7aPN2poVH1ypexeF2CDq2SpZ34WH")
//     override fun convert(source: Jwt): AbstractAuthenticationToken? {
//
//
//     }
// }
