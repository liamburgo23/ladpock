fun Application.routes() {
    routing {
        authenticate("jwt") {
            delete("/api/tickets/{id}") {
                val userId = call.principal<JWTPrincipal>()!!.subject!!
                ticketRepository.deleteOwned(call.parameters["id"]!!, userId)
                call.respond(HttpStatusCode.NoContent)
            }
        }
    }
}
