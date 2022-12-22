#!/usr/bin/env ruby -Ku
# default
$line_len = 60

while $stdin.gets
	$_.chomp!
	if $. == 1
		if /^\d+$/ =~ $_
			$line_len = $_.to_i
		end
	end

	if $_.length > $line_len
		line = $_.gsub(/(.{#{$line_len}})/) {|matched|
			matched.to_s+"\n"
		}
		line.chomp!
	else
		line = $_
	end
	print(line, "\n")
end

exit
