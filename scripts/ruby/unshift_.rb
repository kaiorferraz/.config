#!/usr/bin/env ruby -Ku
while $stdin.gets
	print $_.sub(/^[>'#\t 　]/, "")
end

exit
