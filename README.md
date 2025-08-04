Felt cute might document later idk

### Design Choice:

- The API userActions is stateless, it has no notion of how senseful its arguments are in relation to the authentication state
- most critical input validation points are enforced on the DB and crypto layer,
-  But the primary driver of the authentication state, user Information, input validation and such should be handled by the CLI layer