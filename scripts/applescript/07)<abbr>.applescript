(*
<abbr>.applescript
Sample Script for CotEditor

Description:
Wrap the selection with <abbr> and </abbr> tags.

written by nakamuxu on 2005-03-14
modified by 1024jp on 2015
*)

--
property beginStr : "<abbr title=\"\">"
property endStr : "</abbr>"
property preMargin : 13

--
tell application "CotEditor"
	if not (exists front document) then return
	
	tell front document
		set {loc, len} to range of selection
		
		if (len = 0) then
			set newStr to beginStr & endStr
			if (preMargin = 0) then
				set numOfMove to count of character of beginStr
			else
				set numOfMove to preMargin
			end if
		else if (len > 0) then
			set curStr to contents of selection
			set newStr to beginStr & curStr & endStr
			if (preMargin = 0) then
				set numOfMove to count of character of newStr
			else
				set numOfMove to preMargin
			end if
		else
			return
		end if
		
		set contents of selection to newStr
		set range of selection to {loc + numOfMove, 0}
	end tell
end tell
