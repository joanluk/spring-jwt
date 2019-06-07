package org.emaginalabs.sample.jwt.rest;

import lombok.extern.slf4j.Slf4j;
import org.emaginalabs.sample.jwt.model.Pet;
import org.emaginalabs.sample.jwt.repository.PetRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(value = "/api/pets")
@Slf4j
public class PetController {

    @Autowired
    private PetRepository repository;

    @GetMapping
    @ResponseBody
    public List<Pet> findAll() {
        log.debug("Searching pets");
        return repository.findAll();
    }

    //@PreAuthorize("hasRole('ROLE_Publisher')")
    @PostMapping
    @ResponseBody
    public Pet insert(@RequestBody Pet pet) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.debug("Inserting pet {} ({})", pet, authentication);
        repository.insert(pet);
        return pet;
    }

}
