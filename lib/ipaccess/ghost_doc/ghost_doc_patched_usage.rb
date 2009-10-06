# Access checks are lazy,
# which means they are performed when real connection
# is going to happend.
# 
# Instances of this class will also
# internally use patched versions of Ruby's network
# socket objects to avoid access leaks.
# 
# You can pass access set in various ways: while
# creating new object or while communication is
# already started. You can also rely on global
# access set, which is used by default.
#
# === Usage
# 
# There are 3 ways to enable access control:
#
# * patching original class (see IPAccess.arm) – use it in code that you cannot modify
# * patching single instance (see IPAccess.arm) – use it occasionally
# * using instances of this class directly – use it in your own code
# 
# There are also 3 ways to manage access rules:
# 
# * using new methods like blacklist and whitelist – preferred, ensures that access check is done after change
# * using +acl+ member – you may control only private and shared access sets that way and have to ensure that re-check is done after change
# * using <tt>IPAccess::Global</tt> constant – use it when object is associated with global access set
# 
# The +acl+ member and <tt>IPAccess::Global</tt> are IPAccess objects.
# Direct methods are documented below – they are easy to use
# but their appliance is limited to existing objects (since they
# are instance methods). That sometimes may not be what you need,
# for example in case of quick setups when connection is made in
# the very moment new object is created or when single object is patched
# (armed) in connected state. Remeber to call acl_recheck
# immediately after rules management operation to avoid leaks
# when using +acl+ member or <tt>IPAccess::Global</tt> to manage
# access rules.
