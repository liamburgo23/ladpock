package demo;

import jakarta.ws.rs.*;
import jakarta.annotation.security.RolesAllowed;
import jakarta.annotation.security.PermitAll;

@Path("/api/accounts")
@RolesAllowed("user")
public class AccountResource {
    @Inject SecurityIdentity securityIdentity;

    @DELETE
    @Path("/{id}")
    public void remove(@PathParam("id") Long id) {
        accountRepository.deleteOwned(id, securityIdentity.getPrincipal().getName());
    }

    @GET
    @Path("/plans")
    @PermitAll
    public String plans() {
        return "free";
    }
}
