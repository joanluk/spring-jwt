package org.emaginalabs.sample.jwt.repository;

import org.apache.commons.lang3.StringUtils;
import org.emaginalabs.sample.jwt.model.Pet;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
public class PetRepository {

    private final List<Pet> values;

    private PetRepository() {
        values = new ArrayList<>();
        values.add(Pet.builder().id("1").name("Chin").build());
        values.add(Pet.builder().id("2").name("Chesco").build());
    }

    public List<Pet> findAll() {
        return values;
    }

    public void insert(Pet pet) {
        Assert.notNull(pet, "Missing Pet");
        if (StringUtils.isEmpty(pet.getId())) {
            pet.setId(UUID.randomUUID().toString());
        }
        values.add(pet);
    }

}
