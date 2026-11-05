fun Application.routes() {
    routing {
        route("/api") {
            post("/tickets") {
                val body = call.receive<NewTicket>()
                ticketRepository.save(body)
                call.respond(HttpStatusCode.Created)
            }
            authenticate("jwt") {
                delete("/tickets/{id}") {
                    ticketRepository.delete(call.parameters["id"]!!)
                    call.respond(HttpStatusCode.NoContent)
                }
            }
        }
    }
}
