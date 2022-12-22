#!/usr/bin/env ruby -Ku

whole = Array.new
rev_flag = nil
inv_flag = nil

while $stdin.gets("")
	if $. == 1
		cond = $_.chomp.split("\t")
		if cond[1]
			if /i/i =~ cond[1]
				re = Regexp.new(cond[0], "-i")
			else
				re = Regexp.new(cond[0])
			end
			if /r/i =~ cond[1]
				rev_flag = 1
			end
			if /v/i =~ cond[1]
				inv_flag = 1
			end
		else
			re = Regexp.new(cond[0])
		end
	else
		if inv_flag
			if !(re =~ $_)
				whole << $_
			end
		else
			if re =~ $_
				whole << $_
			end
		end
	end
end

if rev_flag
	whole.reverse!
end

whole.each do |line|
	print line
end


exit
