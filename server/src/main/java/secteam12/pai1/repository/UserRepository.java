package secteam12.pai1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import secteam12.pai1.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
    
}
