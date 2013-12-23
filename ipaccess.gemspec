# -*- encoding: utf-8 -*-
# stub: ipaccess 1.2.0.20131223130056 ruby lib

Gem::Specification.new do |s|
  s.name = "ipaccess"
  s.version = "1.2.0.20131223130056"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Pawe\u{142} Wilk"]
  s.cert_chain = ["/Users/siefca/.gem/gem-public_cert.pem"]
  s.date = "2013-12-23"
  s.description = "This library allows you to control IP access for sockets and other objects"
  s.email = ["pw@gnu.org"]
  s.extra_rdoc_files = ["Manifest.txt"]
  s.files = [".rspec", ".yardopts", "ChangeLog", "LGPL-LICENSE", "Manifest.txt", "README.md", "Rakefile", "docs/COPYING", "docs/FAQ", "docs/HISTORY", "docs/LEGAL", "docs/LGPL", "docs/TODO", "docs/images/ipaccess.png", "docs/images/ipaccess_ac_for_args.png", "docs/images/ipaccess_ac_for_socket.png", "docs/images/ipaccess_logo.png", "docs/images/ipaccess_relations.png", "docs/images/ipaccess_setup_origin.png", "docs/images/ipaccess_setup_origin_tab.png", "docs/images/ipaccess_view.png", "docs/rdoc.css", "examples/ftp.rb", "examples/http.rb", "examples/imap.rb", "examples/pop.rb", "examples/smtp.rb", "examples/tcp_server.rb", "examples/tcp_socket.rb", "examples/telnet.rb", "examples/text_message.rb", "lib/ipaccess.rb", "lib/ipaccess/arm_sockets.rb", "lib/ipaccess/ghost_doc/ghost_doc.rb", "lib/ipaccess/ghost_doc/ghost_doc_acl.rdoc", "lib/ipaccess/ghost_doc/ghost_doc_net_ftp.rb", "lib/ipaccess/ghost_doc/ghost_doc_net_http.rb", "lib/ipaccess/ghost_doc/ghost_doc_net_smtp.rb", "lib/ipaccess/ghost_doc/ghost_doc_net_telnet.rb", "lib/ipaccess/ghost_doc/ghost_doc_p_blacklist.rb", "lib/ipaccess/ghost_doc/ghost_doc_p_blacklist_e.rb", "lib/ipaccess/ghost_doc/ghost_doc_p_unblacklist.rb", "lib/ipaccess/ghost_doc/ghost_doc_p_unblacklist_e.rb", "lib/ipaccess/ghost_doc/ghost_doc_p_unwhitelist.rb", "lib/ipaccess/ghost_doc/ghost_doc_p_unwhitelist_e.rb", "lib/ipaccess/ghost_doc/ghost_doc_p_whitelist.rb", "lib/ipaccess/ghost_doc/ghost_doc_p_whitelist_e.rb", "lib/ipaccess/ghost_doc/ghost_doc_patched_usage.rb", "lib/ipaccess/ghost_doc/ghost_doc_sockets.rb", "lib/ipaccess/ip_access_check.rb", "lib/ipaccess/ip_access_errors.rb", "lib/ipaccess/ip_access_list.rb", "lib/ipaccess/ip_access_set.rb", "lib/ipaccess/net/ftp.rb", "lib/ipaccess/net/http.rb", "lib/ipaccess/net/https.rb", "lib/ipaccess/net/imap.rb", "lib/ipaccess/net/pop.rb", "lib/ipaccess/net/smtp.rb", "lib/ipaccess/net/telnet.rb", "lib/ipaccess/patches/generic.rb", "lib/ipaccess/patches/net_ftp.rb", "lib/ipaccess/patches/net_http.rb", "lib/ipaccess/patches/net_https.rb", "lib/ipaccess/patches/net_imap.rb", "lib/ipaccess/patches/net_pop.rb", "lib/ipaccess/patches/net_smtp.rb", "lib/ipaccess/patches/net_telnet.rb", "lib/ipaccess/patches/netaddr.rb", "lib/ipaccess/patches/sockets.rb", "lib/ipaccess/socket.rb", "lib/ipaccess/sockets.rb", "spec/ip_access_list_spec.rb", "spec/rcov.opts", "spec/spec.opts", ".gemtest"]
  s.homepage = "https://rubygems.org/gems/ipaccess"
  s.rdoc_options = ["--title", "Ipaccess Documentation", "--quiet"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "ipaccess"
  s.rubygems_version = "2.1.11"
  s.signing_key = "/Users/siefca/.gem/gem-private_key.pem"
  s.summary = "IP Access Control for Ruby"

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<netaddr>, [">= 1.5.0"])
      s.add_development_dependency(%q<hoe-yard>, [">= 0.1.2"])
      s.add_development_dependency(%q<rspec>, [">= 2.6.0"])
      s.add_development_dependency(%q<yard>, [">= 0.8.2"])
      s.add_development_dependency(%q<rdoc>, [">= 3.8.0"])
      s.add_development_dependency(%q<redcarpet>, [">= 2.1.0"])
      s.add_development_dependency(%q<bundler>, [">= 1.0.10"])
      s.add_development_dependency(%q<hoe-bundler>, [">= 1.1.0"])
      s.add_development_dependency(%q<hoe-gemspec>, [">= 1.0.0"])
      s.add_development_dependency(%q<hoe>, ["~> 2.16"])
    else
      s.add_dependency(%q<netaddr>, [">= 1.5.0"])
      s.add_dependency(%q<hoe-yard>, [">= 0.1.2"])
      s.add_dependency(%q<rspec>, [">= 2.6.0"])
      s.add_dependency(%q<yard>, [">= 0.8.2"])
      s.add_dependency(%q<rdoc>, [">= 3.8.0"])
      s.add_dependency(%q<redcarpet>, [">= 2.1.0"])
      s.add_dependency(%q<bundler>, [">= 1.0.10"])
      s.add_dependency(%q<hoe-bundler>, [">= 1.1.0"])
      s.add_dependency(%q<hoe-gemspec>, [">= 1.0.0"])
      s.add_dependency(%q<hoe>, ["~> 2.16"])
    end
  else
    s.add_dependency(%q<netaddr>, [">= 1.5.0"])
    s.add_dependency(%q<hoe-yard>, [">= 0.1.2"])
    s.add_dependency(%q<rspec>, [">= 2.6.0"])
    s.add_dependency(%q<yard>, [">= 0.8.2"])
    s.add_dependency(%q<rdoc>, [">= 3.8.0"])
    s.add_dependency(%q<redcarpet>, [">= 2.1.0"])
    s.add_dependency(%q<bundler>, [">= 1.0.10"])
    s.add_dependency(%q<hoe-bundler>, [">= 1.1.0"])
    s.add_dependency(%q<hoe-gemspec>, [">= 1.0.0"])
    s.add_dependency(%q<hoe>, ["~> 2.16"])
  end
end
