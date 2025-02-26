package secteam12.pai1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import secteam12.pai1.model.User;

import javax.sql.RowSet;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);

    RowSet getByid(Integer id);
}
