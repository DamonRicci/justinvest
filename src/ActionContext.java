/**
 * Context for permission checks, carrying the account owner and current hour.
 */
public class ActionContext {
    private final String accountOwner;
    private final int hourOfDay;

    /**
     * Creates a context for evaluating permissions.
     *
     * @param accountOwner username the action targets
     * @param hourOfDay    hour in 24h format (0-23)
     */
    public ActionContext(String accountOwner, int hourOfDay) {
        this.accountOwner = accountOwner;
        this.hourOfDay = hourOfDay;
    }

    /** @return username associated with the action */
    public String getAccountOwner() {
        return accountOwner;
    }

    /** @return hour of day (0-23) when the action is performed */
    public int getHourOfDay() {
        return hourOfDay;
    }
}
