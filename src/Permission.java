/**
 * Permissions that can be exercised by roles in the system.
 */
public enum Permission {
    VIEW_OWN_BALANCE,
    VIEW_OWN_PORTFOLIO,
    VIEW_ADVISOR_DETAILS,
    VIEW_PLANNER_DETAILS,
    MODIFY_OWN_PORTFOLIO,
    VIEW_ALL_CLIENT_ACCOUNTS,
    MODIFY_ALL_PORTFOLIO,
    VIEW_MONEYMARKET_INSTR,
    VIEW_PRIVATE_INSTRUMENTS,

    ACCESS_OUTSIDE_HOURS, // all roles except TELLER
    MANAGE_USERS // only ADMIN
}
