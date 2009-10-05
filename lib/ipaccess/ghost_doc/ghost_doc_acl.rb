# This member selects IPAccess object that will be used to
# control IP access for a socket. You may assign global access set,
# create local access set or use shared set.
# 
# - If an argument is +:global+ it uses global access set.
# - If an argument is +:private+ it creates an empty, private access set.
# - If an argument is an IPAccess object then it is used as external, shared set.
# 
# ==== Global access set
# 
# Global access set is an IPAccess object referenced by contant IPAccess::Global
# It cannot be modified by calling +acl+ attribute. To add or remove rules
# use mentioned constant. By default all sockets with enabled IP access control
# are using this set.
#
# ==== Private access set
# 
# Private access set is an IPAccess object created for socket object.
# You may modify it by referencing to +acl+ member of the socket object.
# 
# Under some circumstances it is possible to share private access set
# – you just have to pass the +acl+ member of a socket to initializer
# of new socket object as shared access set.
# 
# ==== Shared access set
# 
# Shared access set is an IPAccess object that more than one socket
# may use to control IP access. It differs from private access set
# only by operation used to create. The private access set is created
# automatically and shared access set exists before socket object is
# formed.
