package br.com.macorin.securityapi.resources;

import org.keycloak.KeycloakPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
@RequestMapping(value = "/security")
public class SecurityResource {

    /**
     * endpoint sem nenhuma validação de role
     */
    @GetMapping
    public ResponseEntity<Void> isAuthenticated() {
        return ResponseEntity.ok().build();
    }

    /**
     * endpoint onde o usuario tem que ter a role user
     */
    @GetMapping(value = "/has-role")
    @PreAuthorize("hasAnyAuthority('ROLE_user')")
    public ResponseEntity<String> isUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        KeycloakPrincipal principal = (KeycloakPrincipal) authentication.getPrincipal();
        String username = principal.getKeycloakSecurityContext().getToken().getPreferredUsername();
        String email = principal.getKeycloakSecurityContext().getToken().getEmail();
        return ResponseEntity.ok(username + "\n" + email);
    }

    /**
     * endpoint onde o usuario tem que ter a role admin
     */
    @GetMapping(value = "/is-admin")
    @PreAuthorize("hasAnyAuthority('ROLE_admin')")
    public ResponseEntity<Void> isAdmin() {
        return ResponseEntity.ok().build();
    }
}
