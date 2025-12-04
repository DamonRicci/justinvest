/**
 * User entity, that has a role
 */
public class User {
    private final String username;
    private final Role role;

    public User(String username, Role role) {
        this.username = username;
        this.role = role;
    }

    /** @return username of the user */
    public String getUsername() {
        return username;
    }

    /** @return assigned role */
    public Role getRole() {
        return role;
    }
}
