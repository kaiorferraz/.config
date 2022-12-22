#!/usr/bin/env ruby -Ku
while $stdin.gets
	print $_.sub(/^/, "#")
end

exit
