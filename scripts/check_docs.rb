#!/usr/bin/env ruby

require "pathname"
require "uri"

required = %w[
  AGENTS.md
  CHANGELOG.md
  CODE_OF_CONDUCT.md
  CONTRIBUTING.md
  LICENSE
  README.md
  README.zh-CN.md
  SECURITY.md
  SUPPORT.md
  docs/product_spec.md
  docs/product_spec.zh-CN.md
]
missing = required.reject { |path| File.file?(path) }
abort("missing required documentation: #{missing.join(', ')}") unless missing.empty?

english = File.read("README.md", encoding: "UTF-8")
chinese = File.read("README.zh-CN.md", encoding: "UTF-8")
abort("README.md must link to the Chinese entry") unless english.include?("README.zh-CN.md")
abort("README.zh-CN.md must link to the English entry") unless chinese.include?("README.md")

markdown_files = Dir.glob("**/*.md", File::FNM_EXTGLOB).reject { |path| path.start_with?(".git/", ".playwright-cli/", "target/", "dist/") }
markdown_files.each do |path|
  text = File.read(path, encoding: "UTF-8")
  text.scan(/\[[^\]]*\]\(([^)]+)\)/).flatten.each do |target|
    next if target.start_with?("#", "http://", "https://", "mailto:")
    local_target = target.split("#", 2).first
    next if local_target.empty?
    resolved = Pathname.new(path).dirname.join(local_target).cleanpath
    abort("broken local link in #{path}: #{target}") unless resolved.file?
  end
end
