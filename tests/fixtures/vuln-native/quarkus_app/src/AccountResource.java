package demo;

import jakarta.ws.rs.*;
import jakarta.annotation.security.RolesAllowed;

@Path("/api/accounts")
public class AccountResource {
    @POST
    public Account create(Account account) {
        accountRepository.save(account);
        return account;
    }

    @GET
    @Path("/{id}")
    @RolesAllowed("user")
    public Account read(@PathParam("id") Long id) {
        return accountRepository.findById(id);
    }
}
