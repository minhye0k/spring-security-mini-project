package mini.project.springsecurity.api;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("admin")
public class AdminController {

    @GetMapping
    ResponseEntity admin(){
        return ResponseEntity.ok().build();
    }
}
