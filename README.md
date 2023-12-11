# Checking-password-AD
Designed for system administration. Check and send notification of AD user password expiration

This script selects all users of your domain in the specified folders and looks through the last password change, where there is an opportunity to look at the password expiration, if there is no such opportunity, then adds 3 months to the last date of password change and sends the specified recipients to the mail about the need to change the password.
