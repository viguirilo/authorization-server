package com.restaurant.api.authorizationserver.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "user")
@NoArgsConstructor
@AllArgsConstructor
@Data
@JsonRootName(value = "user")
public class User implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonProperty(value = "id")
    private Long id;

    @Column(name = "name", length = 80, nullable = false)
    @JsonProperty(value = "name")
    private String name;

    @Column(name = "email", length = 50, nullable = false)
    @JsonProperty(value = "email")
    private String email;

    @JsonIgnore
    @Column(name = "password", length = 100, nullable = false)
    @JsonProperty(value = "password")
    private String password;

    @CreationTimestamp
    @Column(name = "creation_date", nullable = false, columnDefinition = "datetime")
    @JsonProperty(value = "creationDate")
    private LocalDateTime creationDate;

    @ManyToMany
    @JoinTable(name = "user_group",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "group_id")
    )
    private List<Group> groups = new ArrayList<>();

}
