/// Scope names carried by application tokens, and the rule for checking them.
public enum Scope {
    /// Grants every scope.
    public static let all = "*"
    /// Permission to send notifications through NotificationContext.
    public static let notificationSend = "notification:send"

    /// Whether the scopes a token holds satisfy `required` — either the exact scope or the `*` wildcard.
    public static func grants(_ held: [String], _ required: String) -> Bool {
        held.contains(all) || held.contains(required)
    }
}
