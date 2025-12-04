import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * centralized permission checker mapping roles to permissions and enforcing
 * context on check(s)
 */
public class AccessControl {

    private static final Map<Role, Set<Permission>> ROLE_PERMS = Map.of(

            Role.CLIENT, Set.of(
                    Permission.VIEW_OWN_BALANCE,
                    Permission.VIEW_OWN_PORTFOLIO,
                    Permission.VIEW_ADVISOR_DETAILS,
                    Permission.ACCESS_OUTSIDE_HOURS),

            Role.PREMIUM_CLIENT, Set.of(
                    Permission.VIEW_OWN_BALANCE,
                    Permission.VIEW_OWN_PORTFOLIO,
                    Permission.VIEW_ADVISOR_DETAILS,
                    Permission.VIEW_PLANNER_DETAILS,
                    Permission.MODIFY_OWN_PORTFOLIO,
                    Permission.ACCESS_OUTSIDE_HOURS),

            // only TELLER has time restriction (so doesnt get permission)
            Role.TELLER, Set.of(
                    Permission.VIEW_ALL_CLIENT_ACCOUNTS),

            Role.FINANCIAL_ADVISOR, Set.of(
                    Permission.VIEW_ALL_CLIENT_ACCOUNTS,
                    Permission.MODIFY_ALL_PORTFOLIO,
                    Permission.VIEW_PRIVATE_INSTRUMENTS,
                    Permission.ACCESS_OUTSIDE_HOURS),

            Role.FINANCIAL_PLANNER, Set.of(
                    Permission.VIEW_ALL_CLIENT_ACCOUNTS,
                    Permission.MODIFY_ALL_PORTFOLIO,
                    Permission.VIEW_PRIVATE_INSTRUMENTS,
                    Permission.ACCESS_OUTSIDE_HOURS,
                    Permission.VIEW_MONEYMARKET_INSTR),

            // admin only role with user management permissions
            Role.ADMIN, Set.of(
                    Permission.MANAGE_USERS,
                    Permission.ACCESS_OUTSIDE_HOURS));

    private static final int BUSINESS_HOUR_START = 9; // 9 AM
    private static final int BUSINESS_HOUR_END = 17; // 5 PM

    private static boolean withinBusinessHours(int hour) {
        return hour >= BUSINESS_HOUR_START && hour < BUSINESS_HOUR_END;
    }

    /**
     * determines whether the given user can perform the requested permission in the
     * context
     */
    public static boolean hasPermission(User user, Permission permission, ActionContext context) {
        Role role = user.getRole();
        Set<Permission> perms = ROLE_PERMS.getOrDefault(role, Collections.emptySet());

        // 1st check: if the role has the base permission
        if (!perms.contains(permission)) {
            return false;
        }

        // 2nd check: time restrictions for TELLER role
        if (!withinBusinessHours(context.getHourOfDay())) {
            if (!perms.contains(Permission.ACCESS_OUTSIDE_HOURS)) {
                return false;
            }
        }

        // 3rd check: the own vs any-client rules for "own" permissions
        if (permission == Permission.VIEW_OWN_BALANCE
                || permission == Permission.VIEW_OWN_PORTFOLIO
                || permission == Permission.MODIFY_OWN_PORTFOLIO) {

            return user.getUsername().equals(context.getAccountOwner());
        }

        // "any client" and admin-only permissions are fully covered by role + time
        // so no further checks needed
        return true;
    }
}
