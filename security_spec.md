# Security Specification & Security Rules Design

## 1. Data Invariants
1. **User Identity Boundary**: A user can only access, create, update, or delete passwords and device states located under their own subcollection `/users/{userId}/...`, where `userId == request.auth.uid`.
2. **Identity Integrity**: `userId` in `incoming()` must match `request.auth.uid` and `{userId}` path variable.
3. **Immutability of Identifiers**: `userId` and `id` cannot be modified during updates.
4. **Temporal Invariants**: `createdAt` must be `request.time` upon creation and immutable. `updatedAt` must equal `request.time` on every write/update.
5. **Payload Bounds**: Password fields, names, and state variables are strictly bounded by size and type to prevent injection or denial of wallet resource attacks.
6. **No Blanket Queries**: Querying `passwords` or `device_state` requires authentication where `resource.data.userId == request.auth.uid`.

## 2. The "Dirty Dozen" Payloads
1. **Unauthenticated Read**: Attempting to read another user's password vault without authentication.
2. **Cross-Tenant Read**: User A authenticated attempting to read `/users/userB/passwords/pass1`.
3. **Identity Spoofing Create**: User A attempting to write `/users/userB/passwords/pass1` with `userId: "userB"`.
4. **Mismatched UID Create**: User A writing to `/users/userA/passwords/pass1` with `userId: "userB"`.
5. **Ghost Field Injection**: Adding arbitrary fields like `isAdmin: true` or `shadowField: "evil"` to a password entry.
6. **Oversized Field Attack**: Sending a password string greater than 512 characters or name greater than 120 characters.
7. **Invalid Path ID**: Attempting to create or update with an invalid ID containing path traversal characters like `../../hack`.
8. **Immutability Breach**: Updating an existing password entry to alter `userId` or `createdAt`.
9. **Fake Server Timestamp**: Providing client timestamp instead of `request.time` for `createdAt` or `updatedAt`.
10. **Device State Cross-Tenant Modification**: User A writing to `/users/userB/device_state/current`.
11. **Type Poisoning in Device State**: Setting `length` to a string `"sixty-four"` or a boolean instead of an integer.
12. **Blanket Query Scraping**: Attempting a collectionGroup query across all users' passwords without tenant isolation.

## 3. Test Runner Design
The rules will enforce strict default-deny (`match /{document=**} { allow read, write: if false; }`), validate owner identity (`request.auth.uid == userId`), enforce `isValidPasswordEntry` and `isValidDeviceState` on both create and update, and enforce strict allowed keys.
