package br.com.davejosef.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.davejosef.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository repository;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        var path = request.getServletPath();

        if (path.startsWith("/tasks/")) {

            // get user and password
            String authHeader = request.getHeader("Authorization");

            String authorization = authHeader.substring("Basic".length()).trim();

            byte[] authDecoded = Base64.getDecoder().decode(authorization);
            String[] credentials = new String(authDecoded).split(":");
            String username = credentials[0];
            String password = credentials[1];

            // validate user exists
            var user = this.repository.findByUsername(username);
            if (user == null) {
                response.sendError(401);
            } else {

                // validate password is correct
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVerify.verified) {
                    request.setAttribute("userId", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401);
                }
            }

        } else {
            filterChain.doFilter(request, response);
        }

    }
}
