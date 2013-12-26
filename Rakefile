# encoding: utf-8
# -*- ruby -*-
 
$:.unshift File.join(File.dirname(__FILE__), "lib")

require 'rubygems'
require 'bundler/setup'

require "rake"
require "rake/clean"

gem 'hoe'

require "fileutils"
require 'ipaccess'
require 'hoe'

task :default => [:spec]

desc "install by setup.rb"
task :install do
  sh "sudo ruby setup.rb install"
end

### Gem

Hoe.plugin :bundler
Hoe.plugin :yard
Hoe.plugin :gemspec

Hoe.spec 'ipaccess' do
  developer           "Paweł Wilk", "pw@gnu.org"
  self.version         =  "1.2.5"
  self.rubyforge_name  = 'ipaccess'
  self.summary         = 'IP Access Control for Ruby'
  self.description     = 'This library allows you to control IP access for sockets and other objects'
  self.url             = 'https://rubygems.org/gems/ipaccess'
  self.remote_rdoc_dir = ''
  self.rspec_options   = ['--options', 'spec/spec.opts']
  self.rsync_args      << '--chmod=a+rX'
  self.readme_file     = 'README.md'
  self.history_file    = 'docs/HISTORY'

  require_ruby_version '>= 1.9.2'

  extra_deps          << ["netaddr",">= 1.5.0"]
  extra_dev_deps      << ['rspec',            '>= 2.6.0']     <<
                         ['yard',             '>= 0.8.2']     <<
                         ['rdoc',             '>= 3.8.0']     <<
                         ['redcarpet',        '>= 2.1.0']     <<
                         ['bundler',          '>= 1.0.10']    <<
                         ['hoe-bundler',      '>= 1.1.0']     <<
                         ['hoe-gemspec',      '>= 1.0.0']

  self.spec_extras['rdoc_options'] = proc do |rdoc_options|
      rdoc_options << "--title=IP Access Control for Ruby"
  end

end

task 'Manifest.txt' do
  puts 'generating Manifest.txt from git'
  sh %{git ls-files | grep -v gitignore | grep -v Gemfile > Manifest.txt}
  sh %{git add Manifest.txt}
end

task 'ChangeLog' do
  sh %{git log > ChangeLog}
end

desc "Fix documentation's file permissions"
task :docperm do
  sh %{chmod -R a+rX doc}
end

#task :doc => [:appdoc, :docperm]

### Sign & Publish

desc "Create signed tag in Git"
task :tag do
  sh %{git tag -u #{IPAccess::EMAIL} v#{IPAccess::VERSION} -m 'version #{IPAccess::VERSION}'}
end

desc "Create external GnuPG signature for Gem"
task :gemsign do
  sh %{gpg -u #{IPAccess::EMAIL} -ab pkg/#{IPAccess::NAME}-#{IPAccess::VERSION}.gem -o pkg/#{IPAccess::NAME}-#{IPAccess::VERSION}.gem.sig}
end

