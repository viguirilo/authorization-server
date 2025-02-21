package com.restaurant.api.authorizationserver.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Entity
@Table(name = "permission")
@NoArgsConstructor
@AllArgsConstructor
@Data
@JsonRootName(value = "permission")
public class Permission implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonProperty(value = "id")
    private Long id;

    @Column(name = "name", length = 80, nullable = false)
    @JsonProperty(value = "name")
    private String name;

    @Column(name = "description", length = 255, nullable = false)
    @JsonProperty(value = "description")
    private String description;

}
