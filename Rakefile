$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require "rake"
require "rake/clean"
require 'spec/version'
require 'spec/rake/spectask'
require "rake/rdoctask"
require "fileutils"

task :default => :spec_coverage

desc "install by setup.rb"
task :install do
  sh "sudo ruby setup.rb install"
end

### Docs

desc "Generate documentation for the application"
rd = Rake::RDocTask.new("appdoc") do |rdoc|
  rdoc.rdoc_dir = 'doc/api'
  rdoc.title    = "IP Access Control"
  rdoc.options << '--line-numbers'
  rdoc.options << '--inline-source'
  rdoc.options << '--charset=utf-8'
  rdoc.rdoc_files.include('README')
  rdoc.rdoc_files.include('TODO')
  rdoc.rdoc_files.include('LGPL-LICENSE')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

### Specs

spec_opts = proc{File.read("spec/spec.opts").split}
spec_core_files     = FileList['spec/core_spec.rb']
spec_all_files      = spec_core_files

desc "Run core specs"
Spec::Rake::SpecTask.new("spec_core") do |t|
  t.spec_files = spec_core_files
  t.spec_opts  = spec_opts.call
  t.libs << "lib"
end

desc "Run all specs"
Spec::Rake::SpecTask.new("spec") do |t|
  t.spec_files = spec_all_files
  t.spec_opts  = spec_opts.call
  t.libs << "lib"
end

desc "Check documentation coverage"
task :dcov do
  sh %{find lib -name '*.rb' | xargs dcov}
end

