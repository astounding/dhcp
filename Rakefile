# -*- encoding: utf-8 -*-

require 'pathname'
require 'rubygems'
require 'rubygems/package_task'
require 'rdoc/task'
require 'rake/testtask'

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))
require 'dhcp/version'

gemspec = Gem::Specification.new do |s|
  s.name        = 'dhcp'
  s.version     = DHCP::Version::STRING
  s.authors     = [ 'Aaron D. Gifford' ]
  s.license     = 'MIT'
  s.homepage    = 'http://www.aarongifford.com/computers/dhcp/'
  s.summary     = "dhcp-#{DHCP::Version::STRING}"
  s.description = 'A pure-ruby library for parsing and creating IPv4 DHCP packets (requests or responses)'

  s.add_runtime_dependency 'ffi'
  s.add_runtime_dependency 'ipaddress'
 
  s.rubygems_version  = DHCP::Version::STRING
  s.rubyforge_project = 'dhcp'

  s.files = Pathname.glob([
    '*',
    'lib/*',
    'lib/*/*',
    'bin/*'
  ]).select{|x| File.file?(x)}.map{|x| x.to_s} 
  s.require_paths = [ 'lib' ]
  s.executables   = Pathname.glob(['bin/*']).select{|x| File.file?(x)}.map{|x| x.to_s} 
end

Gem::PackageTask.new(gemspec) do |pkg|
  pkg.need_zip = true
  pkg.need_tar = true
end

RDoc::Task.new do |rdoc|
  rdoc.main     = 'README.rdoc'
  rdoc.rdoc_dir = 'doc'
  rdoc.rdoc_files.include('README.rdoc', 'lib/**/*.rb')
end

Rake::TestTask.new do |t|
  t.test_files = FileList['test/*_test.rb']
  t.verbose = true
end

task :default => [
  'pkg/dhcp-' + DHCP::Version::STRING + '.gem',
  :rdoc,
  :test
]

