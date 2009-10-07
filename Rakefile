# encoding: utf-8
# -*- ruby -*-
 
$:.unshift File.join(File.dirname(__FILE__), "lib")

require 'rubygems'
gem 'hoe', '>=2.3.0'

require "rake"
require "rake/clean"
require 'spec/version'
require 'spec/rake/spectask'

require "fileutils"
require 'ipaccess'

require 'hoe'

#task :default => :spec

desc "install by setup.rb"
task :install do
  sh "sudo ruby setup.rb install"
end

### Gem

Hoe.spec 'ipaccess' do
  self.version         =  "1.0.1"
  self.rubyforge_name  = 'ipaccess'
  self.summary         = 'IP Access Control for Ruby'
  self.description     = 'This library allows you to control IP access for sockets and other objects'
  self.url             = 'http://ipaccess.rubyforge.org/'

  developer           "Paweł Wilk", "pw@gnu.org"
  
  self.remote_rdoc_dir = ''
  self.rspec_options   = ['--options', 'spec/spec.opts']
  self.rsync_args      << '--chmod=a+rX'
  self.readme_file     = 'docs/README'
  self.history_file    = 'docs/HISTORY'

  self.extra_rdoc_files = ["docs/README",
                      "docs/LGPL-LICENSE",
                      "docs/LEGAL", "docs/HISTORY",
                      "docs/COPYING"]

  extra_deps          << ["netaddr",">= 1.5.0"]
  extra_dev_deps      << ['hoe', '>= 2.2']

  self.spec_extras['rdoc_options'] = proc do |rdoc_options|
      rdoc_options << "--title=IP Access Control for Ruby"
  end

end

task :docs do
  
  images = Dir.glob('docs/images/*')
  FileUtils.mkdir 'doc/images' unless Dir.exists? 'doc/images'
  FileUtils.cp_r images, 'doc/images'
  
  ["docs/README.html", "index.html"].each do |ht_name|
    output_f = File.new("doc/#{ht_name}.tempfile", 'w')
    File.foreach("doc/#{ht_name}") do |line|
      line.gsub!('src="../images/ipaccess_logo.png"', 'src="../images/ipaccess_logo.png" align="left" style="margin-right:1em;padding-top:0em;"')
      output_f.write(line)
    end
    output_f.close 
    FileUtils.mv "doc/#{ht_name}.tempfile", "doc/#{ht_name}"
  end

end

#Rake::RDocTask.new('fixdocs') do |rd|
#  rd.main = HOE.readme_file
#  rd.options << '-d' if (`which dot` =~ /\/dot/) unless
#  rd.rdoc_dir = 'doc' 
#  rd.rdoc_files += HOE.spec.require_paths
#  rd.rdoc_files += HOE.spec.extra_rdoc_files
#  rd.options << '--title' << "IP Access Control for Ruby"
#end

task 'Manifest.txt' do
  puts 'generating Manifest.txt from git'
  sh %{git ls-files | grep -v gitignore > Manifest.txt}
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

