Gem::Specification.new do |s|
  s.name = %q{ipaccess}
  s.version = "0.0.2"
  s.date = %q{2009-05-10}
  s.rubyforge_project = %q{ipaccess}
  s.summary = %q{IP Access Control}
  s.description = %q{Classes contained in this library allows you to create and control IP access}
  s.email = %q{pw@gnu.org}
  s.homepage = %q{http://randomseed.pl/ipaccess}
  s.rubyforge_project = %q{ipaccess}
  s.has_rdoc = true
  s.add_dependency('netaddr')
  s.authors = ["Paweł Wilk"]
  s.files = ["lib/ipaccess.rb", "lib/ipaccess/arm_sockets.rb",
            "lib/ipaccess/ip_access.rb", "lib/ipaccess/ip_access_errors.rb",
            "lib/ipaccess/ip_access_list.rb", "lib/ipaccess/ip_access_patches.rb",
            "lib/ipaccess/netaddr_patch.rb", "lib/ipaccess/sockets.rb",
            "lib/ipaccess/ghost_doc.rb", "lib/ipaccess/ghost_doc_acl.rb",
            "docs/LGPL-LICENSE", "Rakefile", "docs/README", "docs/TODO",
            "docs/COPYING", "docs/LEGAL", "docs/DOWNLOAD", "docs/WELCOME",
            "spec/core_spec.rb", "spec/ip_access_list_spec.rb", "spec/rcov.opts",
            "spec/spec.opts" ]
end

