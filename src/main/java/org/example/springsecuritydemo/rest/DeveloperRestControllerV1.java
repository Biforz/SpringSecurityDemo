package org.example.springsecuritydemo.rest;

import org.example.springsecuritydemo.model.Developer;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/v1/developers")
public class DeveloperRestControllerV1 {

    List<Developer> DEVELOPERS = new ArrayList<>();

    {
        DEVELOPERS.add(new Developer(1L, "Ivan", "Ivanov"));
        DEVELOPERS.add(new Developer(2L, "Sergey", "Sergeev"));
        DEVELOPERS.add(new Developer(3L, "Petr", "Petrov"));
    }

    @GetMapping
    public List<Developer> getDevelopers() {
        return DEVELOPERS;
    }

    @GetMapping("/{id}")
    public Developer getById(@PathVariable Long id) {
        return DEVELOPERS.stream().filter(developer -> developer.getId().equals(id)).findFirst().orElse(null);
    }

    @PostMapping
    public Developer create(@RequestBody Developer developer) {
        this.DEVELOPERS.add(developer);
        return developer;
    }

    @DeleteMapping("/{id}")
    public void deleteById(@PathVariable Long id) {
        DEVELOPERS.removeIf(developer -> developer.getId().equals(id));
    }
}
