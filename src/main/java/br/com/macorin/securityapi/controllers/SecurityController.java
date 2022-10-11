package br.com.macorin.securityapi.controllers;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/security")
public class SecurityController {

    /**
     * endpoint sem nenhuma validação de role
     */
    @GetMapping
    public ResponseEntity<Void> isAuthenticated() {
        return ResponseEntity.ok().build();
    }

    /**
     * endpoint para obter informaçoes do usuario
     */
    @GetMapping(value = "/info")
    @PreAuthorize("hasAnyAuthority('ROLE_user') or hasAnyAuthority('ROLE_admin')")
    public ResponseEntity<String> info() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        KeycloakPrincipal principal = (KeycloakPrincipal) authentication.getPrincipal();
        String username = principal.getKeycloakSecurityContext().getToken().getPreferredUsername();
        String email = principal.getKeycloakSecurityContext().getToken().getEmail();
        String scopes = principal.getKeycloakSecurityContext().getToken().getScope();

        //Keycloak.getInstance("http://localhost:28080/auth","pagrn","admin","admin", "auth-pagrn");
        //KeycloakBuilder.builder().serverUrl("http://localhost:28080/auth").realm("pagrn").grantType("password").username("admin").password("admin").clientId("auth-pagrn").clientSecret("f9ec895b-7d36-44aa-820c-c6aaa2c80ad0").build().realm("pagrn").toRepresentation()
        return ResponseEntity.ok(username + "\n" + email + "\n" + scopes);
    }

    /**
     * endpoint onde o usuario tem que ter a role user
     */
    @GetMapping(value = "/user")
    @PreAuthorize("hasAnyAuthority('ROLE_admin')" )
    public ResponseEntity<Void> isUser() {
        return ResponseEntity.ok().build();
    }

    /**
     * endpoint onde o usuario tem que ter a role admin
     */
    @GetMapping(value = "/admin")
    @PreAuthorize("hasAnyAuthority('ROLE_admin')" )
    public ResponseEntity<Void> isAdmin() {
        return ResponseEntity.ok().build();
    }

    /**
     * endpoint onde o usuario tem que ter a role user e funcionario da sead
     */
    @GetMapping(value = "/user_in_sead")
    @PreAuthorize("hasAnyAuthority('ROLE_user')" )
    public ResponseEntity<String> isUserInSEAD() {
        SecurityContext context = SecurityContextHolder.getContext();
        if(context.getAuthentication() != null) {
            KeycloakPrincipal principal = (KeycloakPrincipal) context.getAuthentication().getPrincipal();
            KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
            AccessToken accessToken = session.getToken();
            AccessToken.Access realmAccess = accessToken.getRealmAccess();
            //System.out.println(realmAccess.getRoles());

            if(realmAccess.getRoles().contains("sead")) {
                return ResponseEntity.ok("Permitido, voce e um funcionario na SEAD");
            }
            return ResponseEntity.status(403).body("Nao permitido, voce nao e um funcionario na SEAD");
        }
        return ResponseEntity.status(403).body("Not allowed");
    }
}
