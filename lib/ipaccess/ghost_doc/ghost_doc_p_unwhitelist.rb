# :call-seq:
#   unwhitelist(*addresses)<br />
#   unwhitelist(list, *addresses)
# 
# This method removes whitelisted IP address(-es)
# from the input or output access list selected
# by the *list* argument (+:input+ or +:output+).
# If the access list selector is omited it
# operates on the default access list that certain
# kind of network object uses. The allowed format of address
# is the same as for IPAccessList.obj_to_cidr.
# This method will not add nor remove any
# blacklisted item.
# 
# === Restrictions
# 
# This method won't allow you to modify the list if
# the global access set is associated with an object.
# You may operate on IPAccess::Global or use
# unwhitelist! instead.
# 
# === Return value
# 
# It will return the result of calling
# IPAccessList#unwhitelist on the list.    
# 
# === Revalidation
#
# After modyfing access set current connection
# is validated again to avoid access leaks.
# 
# === DNS Warning
#
# You should avoid passing hostnames as arguments since
# DNS is not reliable and responses may change with time,
# which may cause security flaws.