$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require "rake"
require "rake/clean"
require 'rcov/rcovtask'
require 'spec/version'
require 'spec/rake/spectask'
require "rake/rdoctask"
require "fileutils"

task :default => :spec_coverage

desc "install by setup.rb"
task :install do
  sh "sudo ruby setup.rb install"
end

### Specs

spec_opts = proc{File.read("spec/spec.opts").split}
rcov_opts = proc{File.read("spec/rcov.opts").split}
spec_core_files     = FileList['spec/core_spec.rb']
spec_all_files      = spec_core_files

desc "Run core and model specs with coverage"
Spec::Rake::SpecTask.new("spec_coverage") do |t|
  t.spec_files = FileList['spec/core_spec.rb']
  t.spec_opts  = spec_opts.call
  t.rcov_opts  = rcov_opts.call
  t.rcov = true
end
 
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
