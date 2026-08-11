#!/usr/bin/env ruby

require "uri"

urls = Dir.glob("**/*.md").reject { |path| path.start_with?(".git/", ".playwright-cli/", "target/", "dist/") }.flat_map do |path|
  text = File.read(path, encoding: "UTF-8")
  inline = text.scan(/\]\((https:\/\/[^)\s]+)\)/).flatten
  references = text.scan(/^\[[^\]]+\]:\s+(https:\/\/\S+)/).flatten
  autolinks = text.scan(/<(https:\/\/[^>\s]+)>/).flatten
  inline + references + autolinks
end
invalid = urls.uniq.reject do |url|
  uri = URI.parse(url)
  uri.is_a?(URI::HTTPS) && !uri.host.to_s.empty?
rescue URI::InvalidURIError
  false
end
abort("invalid external HTTPS links: #{invalid.join(', ')}") unless invalid.empty?
puts "Validated #{urls.uniq.length} external HTTPS links."
