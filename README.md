# EmperorsAuth - login/register for Emperors SMP

Paper 1.21.11 - Java 21

## Build
    mvn clean package
Jar: target/EmperorsAuth-1.0.0.jar -> drop into /plugins, restart.

## Commands
/register <pw> <pw>, /login <pw>, /changepassword <old> <new>, /logout, /unregister <pw>
Admin (emperorsauth.admin): /eauth reload | info <p> | unregister <p> | setpassword <p> <pw> | forcelogin <p>

## Permissions
emperorsauth.admin (op), emperorsauth.bypass (none)

## API
EmperorsAuth.isAuthenticated(player)
