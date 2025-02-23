package secteam12.pai1.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import secteam12.pai1.model.Salt;

public interface SaltRepository extends JpaRepository<Salt, Long>{
    
}
