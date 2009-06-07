# encoding: utf-8
# -*- ruby -*-
 
$:.unshift File.join(File.dirname(__FILE__), "lib")

require 'rubygems'
gem 'hoe', '>=2.0.0'
require 'hoe'

require "rake"
require "rake/clean"
require 'spec/version'
require 'spec/rake/spectask'

require "fileutils"
require 'ipaccess'

require 'rdoc'
require "rake/rdoctask"

task :default => :spec

desc "install by setup.rb"
task :install do
  sh "sudo ruby setup.rb install"
end

### Gem

Hoe.new IPAccess::NAME do |hoe|
  hoe.version = IPAccess::VERSION
  hoe.summary = IPAccess::SUMMARY
  hoe.description = IPAccess::DESC
  hoe.email = IPAccess::EMAIL
  hoe.url = IPAccess::HOMEPAGE
  hoe.rubyforge_name = IPAccess::NAME
  hoe.author = IPAccess::AUTHOR
  hoe.remote_rdoc_dir = ''
  hoe.extra_dev_deps = [["netaddr",">= 1.5.0"]]
  hoe.rspec_options = ['--options', 'spec/spec.opts']
  hoe.readme_file = 'docs/README'
  hoe.history_file = 'docs/HISTORY'
  hoe.extra_rdoc_files = ["docs/README", "docs/USAGE",
                          "docs/LGPL-LICENSE",
                          "docs/LEGAL", "docs/HISTORY",
                          "docs/COPYING"]
end

task 'Manifest.txt' do
  puts 'generating Manifest.txt from git'
  sh %{git ls-files > Manifest.txt}
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

### Specs

#spec_opts = proc{File.read("spec/spec.opts").split}
#spec_core_files     = FileList['spec/core_spec.rb']
#spec_all_files      = spec_core_files

#desc "Run core specs"
#Spec::Rake::SpecTask.new("spec_core") do |t|
#  t.spec_files = spec_core_files
#  t.spec_opts  = spec_opts.call
#  t.libs << "lib"
#end
#
#desc "Run all specs"
#Spec::Rake::SpecTask.new("spec") do |t|
#  t.spec_files = spec_all_files
#  t.spec_opts  = spec_opts.call
#  t.libs << "lib"
#end
#
#desc "Check documentation coverage"
#task :dcov do
#  sh %{find lib -name '*.rb' | xargs dcov}
#end

