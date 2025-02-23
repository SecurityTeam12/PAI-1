package secteam12.pai1.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@Entity
@Table(name = "users")
public class Salt {

    @Id
	@SequenceGenerator(name = "entity_seq", 
        sequenceName = "entity_sequence", 
        initialValue = 100)
	@GeneratedValue(strategy = GenerationType.SEQUENCE	, generator = "entity_seq")
	protected Integer id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String hash;

    @Column(nullable = false)
    private String salt;

}

