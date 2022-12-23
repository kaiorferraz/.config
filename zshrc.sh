#https://github.com/kaiorferraz/.config/blob/master/zshrc.sh
#umask 077

#setopt
setopt PROMPT_SUBST
setopt ALWAYSTOEND
setopt AUTOCD
setopt COMPLETEINWORD
setopt CORRECT
setopt NOBEEP
# setopt NOCLOBBER
# setopt NULLGLOB
# setopt HIST_EXPIRE_DUPS_FIRST
# setopt HISTREDUCEBLANKS
# setopt HIST_IGNORE_DUPS
# setopt HIST_IGNORE_ALL_DUPS
# setopt HIST_FIND_NO_DUPS
# setopt hist_ignore_space
# setopt extendedglob
# setopt extendedhistory
# setopt histignorealldups
# setopt histignorespace
# setopt autopushd

#bindkey
# bindkey "$(echotc kl)" backward-char
# bindkey "$(echotc kr)" forward-char
# bindkey "$(echotc ku)" up-line-or-history
# bindkey "$(echotc kd)" down-line-or-history
# bindkey "\e[1;5D" backward-word
# bindkey "\e[1;5C" forward-word
# bindkey '\t' autosuggest-accept

#variables
HISTSIZE=10000
SAVEHIST=$HISTSIZE
GITHUB_USER="kaio"
TODAY="$(date +%m-%d-%Y)"
NOW="$(date +%F-%H:%M:%S)"
HISTFILE="$HOME/.histfile"
REACT_DIR="$HOME/Developer/React"
PYTHON_DIR="$HOME/Developer/Python"
FLUTTER_DIR="$HOME/Developer/Flutter"
ZDOTDIR="$HOME/.config"

#exports
export NVM_DIR="$CONFIG/.nvm"
export GEM_HOME="$HOME/.gem"
export PATH=$GEM_HOME/bin:$PATH

export CHROME_EXECUTABLE="$HOME/Applications/Chromium.app/Contents/MacOS/Chromium"

export LANG="en_US.UTF-8"
export LC_ALL="en_US.UTF-8"
export LC_CTYPE="en_US.UTF-8"
export LC_MESSAGES="en_US.UTF-8"
export LC_MONETARY="en_US.UTF-8"
export LC_NUMERIC="en_US.UTF-8"
export LC_TIME="en_US.UTF-8"

export HOMEBREW_CASK_OPTS=--require-sha
export HOMEBREW_NO_ANALYTICS=1
export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_INSECURE_REDIRECT=1
# export HOMEBREW_NO_INSTALL_CLEANUP=1
# export HOMEBREW_NO_INSTALL_UPGRADE=1
# export PYTHONSTARTUP="$CONFIG/pythonrc"

#apps
facetime="/System/Applications/FaceTime.app"
messages="/System/Applications/Messages.app"
photo="/System/Applications/Photo Booth.app"
contacts="/System/Applications/Contacts.app"

#plugins
source $CONFIG/plugins/zsh-fast-syntax-highlighting/fast-syntax-highlighting.plugin.zsh
FPATH=$CONFIG/plugins/zsh-completions:$FPATH

#aliase
alias today="date -u +%m.%d.%y"
alias time="date -u +%T"
alias fl="flutter"
alias yt="youtube-dl --restrict-filenames --no-overwrites --write-info-json --write-thumbnail --no-call-home --force-ipv4 --format 'best[height<=720]'"
alias yt_max="youtube-dl --restrict-filenames --no-overwrites --write-info-json --write-thumbnail --no-call-home --force-ipv4"
alias zshrc="code $CONFIG/zshrc.sh"
alias push="git push"
alias pull="/;'>≤git pull"
alias status="git status"
alias commit="git commit -m"
alias add="git add"
alias func="functions"
alias c="clear"
alias z="zsh"
alias l="ls -lhAGF"
alias ll="ls -lhAGF1"
alias rm="rm -drf"
alias grep="grep --text --color"
alias td="mkdir $TODAY ; cd $TODAY"
alias sha="shasum -a 256"
alias hide="chflags hidden $@"
alias md="mkdir -p"
alias pc="pbcopy"
alias pp="pbpaste"
alias santa="santactl"
alias 700="chmod 700"
alias 000="chmod 000"
alias 755="chmod 755"
alias doctor="brew doctor"
alias web="open -a Safari"
alias speed="networkQuality"
alias .="open ."
alias ..="cd .."
alias ...="cd ../.."
alias ....="cd ../../.."

#zsh completions configrations
zstyle ':completion:*' menu select
zstyle ':completion:*' select-prompt %SScrolling active: current selection at %p%s
zstyle ":completion:*" ignore-parents parent pwd
zstyle ":completion:*" auto-description "specify %d"
zstyle ":completion:*" file-sort modification reverse
zstyle ":completion:*" format "completing %d"
zstyle ":completion:*" group-name ""
zstyle ":completion:*" list-colors "=(#b) #([0-9]#)*=36=31"
zstyle ":completion:*" menu select=long-list select=0
zstyle ":completion:*" verbose yes
zstyle ':completion:*' accept-exact '*(N)'
zstyle ':completion:*' completer _complete _ignored _approximate

#functions
function replace {
	sed -i '' "s/$2/$3/g" $1
}

function t {
	if command -v tree >/dev/null; then
		tree --dirsfirst --sort=name -LlaC 1 $@
	else
		l
	fi
}

function block {
	sudo santactl rule --silent-block --path $1
}

function unblock {
	sudo santactl rule --remove --path $1
}

function proxy {
	if [[ -e $CONFIG/proxy_list.txt ]]; then
		rm -rf $CONFIG/proxy_list.txt
	fi
	curl -sSf "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt" \
		>$CONFIG/proxy_list.txt
}

function install {
	if [[ $1 == 'brew' ]]; then
		if [[ $2 == 'local' ]]; then
			cd $CONFIG &&
				mkdir homebrew && curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip 1 -C homebrew
				$CONFIG/homebrew/bin/brew update
				$CONFIG/homebrew/bin/brew upgrade
				z
				echo "Brew installed successfully"
		else
			/bin/bash -c \
				"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
			brew -v update &&
				brew -v upgrade
		fi
	elif [[ $1 == 'flutter' ]]; then
		brew install flutter
		sudo softwareupdate --install-rosetta --agree-to-license
		gem install cocoapods
		gem uninstall ffi && sudo gem install ffi -- --enable-libffi-alloc
	else
		brew -v install $@
	fi
}

function reinstall {
	brew -v reinstall $@
}

function wifi {
	if [[ $1 == "down" ]]; then
		sudo ifconfig en0 down
	elif [[ $1 == "up" ]]; then
		sudo ifconfig en0 up
	elif [[ $1 == "name" ]]; then
		networksetup -getairportnetwork en0 | awk '{print $4}'
	else
		echo "You haven't included any arguments"
	fi
}
function here {
	open $(pwd)
}

function finder {
	mdfind -name $1 | grep $1 --color=auto
}

function get_plist {
	for the_path in $(
		finder LaunchDaemons
		finder LaunchAgents
	); do
		for the_file in $(ls -1 $the_path); do
			echo $the_path/$the_file
		done
	done
}

function plist {
	function get_shasum {
		for i in $(get_plist); do
			shasum -a 256 $i
		done
	}
	if [[ $1 == "get" ]]; then
		if [[ -f $CONFIG/plist_shasum.txt ]]; then
			rm $CONFIG/plist_shasum.txt
		fi
		get_shasum >$CONFIG/plist_shasum.txt
	elif [[ $1 == "verify" ]]; then
		diff <(get_shasum) <(cat $CONFIG/plist_shasum.txt)
	else
		get_shasum
	fi
}

function remove {
	if [[ $1 == 'brew' ]]; then
		/bin/bash -c \
			"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/uninstall.sh)"
		if [[ -d "$CONFIG/homebrew" ]]; then
			brew -v cleanup
			rm -rf $CONFIG/homebrew
		elif [[ -d "/opt/homebrew" ]]; then
			brew -v cleanup
			rm -rf /opt/homebrew
		fi
	else
		brew -v uninstall $@
	fi
}

function generate_ip {
	for a in {1..254}; do
		echo "$a.1.1.1"
		for b in {1..254}; do
			echo "$a.$b.1.1"
			for c in {1..254}; do
				echo "$a.$b.$c.1"
				for d in {1..254}; do
					echo "$a.$b.$c.$d"
				done
			done
		done
	done
}

function connect {
	if [[ $1 == "ubuntu" ]]; then
		ssh root@164.92.89.226 -i $HOME/.ssh/ed25519-ubuntu-odigitalocean-one
	fi
}

function dmg {
	if [[ $1 == "crypt" ]]; then
		hdiutil create $2.dmg -encryption -size $3 -volname $2 -fs JHFS+
	else
		hdiutil create $1.dmg -size $2 -volname $1 -fs JHFS+
	fi
}

function update {
	brew update
	brew upgrade
}

function cleanup {
	brew cleanup
	brew autoremove
}
function info {
	brew info $@
}

function list {
	brew list
}

function search {
	brew search $@
}

function pyenv {
	if [[ -d $HOME ]]; then
		cd $
	fi
	python3 -m venv $1
	cd $1
	source bin/activate
	pip install --upgrade pip
	if [[ -f "requirements.txt" ]]; then
		pip install -r requirements.txt
	fi
}

function cloud {
	cd "~/Library/Mobile\ Documents/com\~apple\~CloudDocs"
}

function clone {
	cd ~/Developer/GitHub
	echo "$@" | cut -d "/" -f 5 | pbcopy
	git clone --dissociate $@
	cd $(pbpaste)
	t
}

function intel {
	exec arch -x86_64 $SHELL
}

function arm64 {
	exec arch -arm64 $SHELL
}

function grep_line {
	grep -n $1 $2
}

function get_ip {
	dig +short $1
}

function dump {
	if [[ $1 == "arp" ]]; then
		sudo tcpdump $NETWORK -w arp-$NOW.pcap "ether proto 0x0806"
	elif [[ $1 == "icmp" ]]; then
		sudo tcpdump -ni $NETWORK -w icmp-$NOW.pcap "icmp"
	elif [[ $1 == "pflog" ]]; then
		sudo tcpdump -ni pflog0 -w pflog-$NOW.pcap "not icmp6 and not host ff02::16 and not host ff02::d"
	elif [[ $1 == "syn" ]]; then
		sudo tcpdump -ni $NETWORK -w syn-$NOW.pcap "tcp[13] & 2 != 0"
	elif [[ $1 == "upd" ]]; then
		sudo tcpdump -ni $NETWORK -w udp-$NOW.pcap "udp and not port 443"
	else
		sudo tcpdump
	fi
}

function ip {
	curl -sq4 "https://icanhazip.com/"
}

function lower {
	tr '[:upper:]' '[:lower:]'
}

function upper {
	tr '[:lower:]' '[:upper:]'
}

function history {
	if [[ $1 == "top" ]]; then
		history 1 | awk '{CMD[$2]++;count++;}END {
		for (a in CMD)print CMD[a] " " CMD[a]/count*100 "% " a;}' | column -c3 -s " " -t | sort -nr |
			nl | head -n25
	elif [[ $1 == "clear" || "clean" ]]; then
		awk '!a[$0]++' $HOME/.histfile >$HOME/.histfile.tmp && mv $HOME/.histfile.tmp $HOME/.histfile
	fi
}

function rand {
	if [[ $1 == "-u" ]] || [[ $1 == "user" ]]; then
		openssl rand -base64 64 | tr -d "=+/1-9" | cut -c-16 | head -1 | lower | pc
		pp
	elif [[ $1 == "-p" ]] || [[ $1 == "pass" ]]; then
		openssl rand -base64 300 | tr -d "=+/" | cut -c12-20 | tr '\n' '-' | cut -b -26 | pc
		pp
	elif [[ $1 == "-l" ]] || [[ $1 == "line" ]]; then
		awk 'BEGIN{srand();}{if (rand() <= 1.0/NR) {x=$0}}END{print x}' $2
	else
		echo "usage: rand [-u user] [-p password len] [-l line]"
	fi
}

# maintaned by Shortcuts.app
# function light {
# 	osascript -e 'tell application "System Events" to tell appearance preferences to set dark mode to not dark mode'
# 	osascript -e 'tell application "System Events" to tell every desktop to set picture to "/Users/kaio/.config/light.png"'
# 	killall Terminal
# 	osascript -e 'tell application "Terminal" to open'
# }

# function dark {
# 	osascript -e 'tell application "System Events" to tell appearance preferences to set dark mode to not dark mode' &&
# 		osascript -e 'tell application "System Events" to tell every desktop to set picture to "/Users/kaio/.config/dark.png"' &&
# 		killall Terminal
# 	osascript -e 'tell application "Terminal" to open'
# }

function bat {
	pmset -g batt | egrep "([0-9]+\%).*" -o --colour=auto | cut -f1 -d';'
}

function pf {
	if [[ $1 == "up" ]]; then
		sudo pfctl -e -f $CONFIG/pf/pf.conf
	elif [[ $1 == "down" ]]; then
		sudo pfctl -d
	elif [[ $1 == "status" ]]; then
		sudo pfctl -s info
	elif [[ $1 == "reload" ]]; then
		sudo pfctl -f /etc/pf.conf
	elif [[ $1 == "log" ]]; then
		sudo pfctl -s nat
	elif [[ $1 == "flush" ]]; then
		sudo pfctl -F all -f /etc/pf.conf
	elif [[ $1 == "show" ]]; then
		sudo pfctl -s rules
	else
		sudo pfctl
	fi
}

function branch_name {
	git branch 2>/dev/null | sed -n -e 's/^\* \(.*\)/(\1) /p'
}

function len {
	echo -n $1 | wc -c
}

function wrap {
	if [[ $1 == "on" ]]; then
		tput rmam
	elif [[ $1 == "off" ]]; then
		tput smam
	else
		echo "\n\nDefine word wrapping within terminal\n\nUsage: wrap on|off\n\n"
	fi
}

function path {
	if [[ -d $1 ]]; then
		export PATH="$1:$PATH"
	fi
}

#paths
path "/bin"
path "/sbin"
path "/usr/bin"
path "/usr/sbin"
path "/usr/local/bin"
path "/usr/local/sbin"
if [[ -d "$CONFIG/flutter/bin" ]]; then
	path "$CONFIG/flutter/bin"
	path "$CONFIG/flutter/sbin"
fi
if [[ -d "$CONFIG/homebrew/bin" ]]; then
	path "$CONFIG/homebrew/bin"
elif [[ -d "/opt/homebrew/bin" ]]; then
	path "/opt/homebrew/bin"
	path "/opt/homebrew/sbin"
fi

autoload -U colors && colors
autoload -Uz compinit
compinit

compdef '_brew uninstall' uninstall
compdef '_brew install' install
compdef '_brew search' search
compdef '_brew update' update
compdef '_brew list' list
compdef '_youtube-dl' yt
compdef '_flutter' fl
compdef '_tree' t

#prompt
# prompt='%F{cyan}%h %F{green}%B%d%F{magenta}%b $(branch_name)%f➜ '
# prompt='%F{red}% $(branch_name)%f➜ '
prompt='%F{cyan}%h %F{green}%B%~%F{red}%b $(branch_name)%f
➜ '

#nvm
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"

#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
###################
# Autosuggestions #
###################

(( ! ${+ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE} )) &&
typeset -g ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'

# Prefix to use when saving original versions of bound widgets
(( ! ${+ZSH_AUTOSUGGEST_ORIGINAL_WIDGET_PREFIX} )) &&
typeset -g ZSH_AUTOSUGGEST_ORIGINAL_WIDGET_PREFIX=autosuggest-orig-

# Strategies to use to fetch a suggestion
# Will try each strategy in order until a suggestion is returned
(( ! ${+ZSH_AUTOSUGGEST_STRATEGY} )) && {
	typeset -ga ZSH_AUTOSUGGEST_STRATEGY
	ZSH_AUTOSUGGEST_STRATEGY=(history)
}

# Widgets that clear the suggestion
(( ! ${+ZSH_AUTOSUGGEST_CLEAR_WIDGETS} )) && {
	typeset -ga ZSH_AUTOSUGGEST_CLEAR_WIDGETS
	ZSH_AUTOSUGGEST_CLEAR_WIDGETS=(
		history-search-forward
		history-search-backward
		history-beginning-search-forward
		history-beginning-search-backward
		history-substring-search-up
		history-substring-search-down
		up-line-or-beginning-search
		down-line-or-beginning-search
		up-line-or-history
		down-line-or-history
		accept-line
		copy-earlier-word
	)
}

# Widgets that accept the entire suggestion
(( ! ${+ZSH_AUTOSUGGEST_ACCEPT_WIDGETS} )) && {
	typeset -ga ZSH_AUTOSUGGEST_ACCEPT_WIDGETS
	ZSH_AUTOSUGGEST_ACCEPT_WIDGETS=(
		forward-char
		end-of-line
		vi-forward-char
		vi-end-of-line
		vi-add-eol
	)
}

# Widgets that accept the entire suggestion and execute it
(( ! ${+ZSH_AUTOSUGGEST_EXECUTE_WIDGETS} )) && {
	typeset -ga ZSH_AUTOSUGGEST_EXECUTE_WIDGETS
	ZSH_AUTOSUGGEST_EXECUTE_WIDGETS=(
	)
}

# Widgets that accept the suggestion as far as the cursor moves
(( ! ${+ZSH_AUTOSUGGEST_PARTIAL_ACCEPT_WIDGETS} )) && {
	typeset -ga ZSH_AUTOSUGGEST_PARTIAL_ACCEPT_WIDGETS
	ZSH_AUTOSUGGEST_PARTIAL_ACCEPT_WIDGETS=(
		forward-word
		emacs-forward-word
		vi-forward-word
		vi-forward-word-end
		vi-forward-blank-word
		vi-forward-blank-word-end
		vi-find-next-char
		vi-find-next-char-skip
	)
}

# Widgets that should be ignored (globbing supported but must be escaped)
(( ! ${+ZSH_AUTOSUGGEST_IGNORE_WIDGETS} )) && {
	typeset -ga ZSH_AUTOSUGGEST_IGNORE_WIDGETS
	ZSH_AUTOSUGGEST_IGNORE_WIDGETS=(
		orig-\*
		beep
		run-help
		set-local-history
		which-command
		yank
		yank-pop
		zle-\*
	)
}

# Pty name for capturing completions for completion suggestion strategy
(( ! ${+ZSH_AUTOSUGGEST_COMPLETIONS_PTY_NAME} )) &&
typeset -g ZSH_AUTOSUGGEST_COMPLETIONS_PTY_NAME=zsh_autosuggest_completion_pty

#--------------------------------------------------------------------#
# Utility Functions                                                  #
#--------------------------------------------------------------------#

_zsh_autosuggest_escape_command() {
	setopt localoptions EXTENDED_GLOB

	# Escape special chars in the string (requires EXTENDED_GLOB)
	echo -E "${1//(#m)[\"\'\\()\[\]|*?~]/\\$MATCH}"
}

#--------------------------------------------------------------------#
# Widget Helpers                                                     #
#--------------------------------------------------------------------#

_zsh_autosuggest_incr_bind_count() {
	typeset -gi bind_count=$((_ZSH_AUTOSUGGEST_BIND_COUNTS[$1]+1))
	_ZSH_AUTOSUGGEST_BIND_COUNTS[$1]=$bind_count
}

# Bind a single widget to an autosuggest widget, saving a reference to the original widget
_zsh_autosuggest_bind_widget() {
	typeset -gA _ZSH_AUTOSUGGEST_BIND_COUNTS

	local widget=$1
	local autosuggest_action=$2
	local prefix=$ZSH_AUTOSUGGEST_ORIGINAL_WIDGET_PREFIX

	local -i bind_count

	# Save a reference to the original widget
	case $widgets[$widget] in
		# Already bound
		user:_zsh_autosuggest_(bound|orig)_*)
			bind_count=$((_ZSH_AUTOSUGGEST_BIND_COUNTS[$widget]))
			;;

		# User-defined widget
		user:*)
			_zsh_autosuggest_incr_bind_count $widget
			zle -N $prefix$bind_count-$widget ${widgets[$widget]#*:}
			;;

		# Built-in widget
		builtin)
			_zsh_autosuggest_incr_bind_count $widget
			eval "_zsh_autosuggest_orig_${(q)widget}() { zle .${(q)widget} }"
			zle -N $prefix$bind_count-$widget _zsh_autosuggest_orig_$widget
			;;

		# Completion widget
		completion:*)
			_zsh_autosuggest_incr_bind_count $widget
			eval "zle -C $prefix$bind_count-${(q)widget} ${${(s.:.)widgets[$widget]}[2,3]}"
			;;
	esac

	# Pass the original widget's name explicitly into the autosuggest
	# function. Use this passed in widget name to call the original
	# widget instead of relying on the $WIDGET variable being set
	# correctly. $WIDGET cannot be trusted because other plugins call
	# zle without the `-w` flag (e.g. `zle self-insert` instead of
	# `zle self-insert -w`).
	eval "_zsh_autosuggest_bound_${bind_count}_${(q)widget}() {
		_zsh_autosuggest_widget_$autosuggest_action $prefix$bind_count-${(q)widget} \$@
	}"

	# Create the bound widget
	zle -N -- $widget _zsh_autosuggest_bound_${bind_count}_$widget
}

# Map all configured widgets to the right autosuggest widgets
_zsh_autosuggest_bind_widgets() {
	emulate -L zsh

 	local widget
	local ignore_widgets

	ignore_widgets=(
		.\*
		_\*
		${_ZSH_AUTOSUGGEST_BUILTIN_ACTIONS/#/autosuggest-}
		$ZSH_AUTOSUGGEST_ORIGINAL_WIDGET_PREFIX\*
		$ZSH_AUTOSUGGEST_IGNORE_WIDGETS
	)

	# Find every widget we might want to bind and bind it appropriately
	for widget in ${${(f)"$(builtin zle -la)"}:#${(j:|:)~ignore_widgets}}; do
		if [[ -n ${ZSH_AUTOSUGGEST_CLEAR_WIDGETS[(r)$widget]} ]]; then
			_zsh_autosuggest_bind_widget $widget clear
		elif [[ -n ${ZSH_AUTOSUGGEST_ACCEPT_WIDGETS[(r)$widget]} ]]; then
			_zsh_autosuggest_bind_widget $widget accept
		elif [[ -n ${ZSH_AUTOSUGGEST_EXECUTE_WIDGETS[(r)$widget]} ]]; then
			_zsh_autosuggest_bind_widget $widget execute
		elif [[ -n ${ZSH_AUTOSUGGEST_PARTIAL_ACCEPT_WIDGETS[(r)$widget]} ]]; then
			_zsh_autosuggest_bind_widget $widget partial_accept
		else
			# Assume any unspecified widget might modify the buffer
			_zsh_autosuggest_bind_widget $widget modify
		fi
	done
}

# Given the name of an original widget and args, invoke it, if it exists
_zsh_autosuggest_invoke_original_widget() {
	# Do nothing unless called with at least one arg
	(( $# )) || return 0

	local original_widget_name="$1"

	shift

	if (( ${+widgets[$original_widget_name]} )); then
		zle $original_widget_name -- $@
	fi
}

#--------------------------------------------------------------------#
# Highlighting                                                       #
#--------------------------------------------------------------------#

# If there was a highlight, remove it
_zsh_autosuggest_highlight_reset() {
	typeset -g _ZSH_AUTOSUGGEST_LAST_HIGHLIGHT

	if [[ -n "$_ZSH_AUTOSUGGEST_LAST_HIGHLIGHT" ]]; then
		region_highlight=("${(@)region_highlight:#$_ZSH_AUTOSUGGEST_LAST_HIGHLIGHT}")
		unset _ZSH_AUTOSUGGEST_LAST_HIGHLIGHT
	fi
}

# If there's a suggestion, highlight it
_zsh_autosuggest_highlight_apply() {
	typeset -g _ZSH_AUTOSUGGEST_LAST_HIGHLIGHT

	if (( $#POSTDISPLAY )); then
		typeset -g _ZSH_AUTOSUGGEST_LAST_HIGHLIGHT="$#BUFFER $(($#BUFFER + $#POSTDISPLAY)) $ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE"
		region_highlight+=("$_ZSH_AUTOSUGGEST_LAST_HIGHLIGHT")
	else
		unset _ZSH_AUTOSUGGEST_LAST_HIGHLIGHT
	fi
}

#--------------------------------------------------------------------#
# Autosuggest Widget Implementations                                 #
#--------------------------------------------------------------------#

# Disable suggestions
_zsh_autosuggest_disable() {
	typeset -g _ZSH_AUTOSUGGEST_DISABLED
	_zsh_autosuggest_clear
}

# Enable suggestions
_zsh_autosuggest_enable() {
	unset _ZSH_AUTOSUGGEST_DISABLED

	if (( $#BUFFER )); then
		_zsh_autosuggest_fetch
	fi
}

# Toggle suggestions (enable/disable)
_zsh_autosuggest_toggle() {
	if (( ${+_ZSH_AUTOSUGGEST_DISABLED} )); then
		_zsh_autosuggest_enable
	else
		_zsh_autosuggest_disable
	fi
}

# Clear the suggestion
_zsh_autosuggest_clear() {
	# Remove the suggestion
	unset POSTDISPLAY

	_zsh_autosuggest_invoke_original_widget $@
}

# Modify the buffer and get a new suggestion
_zsh_autosuggest_modify() {
	local -i retval

	# Only available in zsh >= 5.4
	local -i KEYS_QUEUED_COUNT

	# Save the contents of the buffer/postdisplay
	local orig_buffer="$BUFFER"
	local orig_postdisplay="$POSTDISPLAY"

	# Clear suggestion while waiting for next one
	unset POSTDISPLAY

	# Original widget may modify the buffer
	_zsh_autosuggest_invoke_original_widget $@
	retval=$?

	emulate -L zsh

	# Don't fetch a new suggestion if there's more input to be read immediately
	if (( $PENDING > 0 || $KEYS_QUEUED_COUNT > 0 )); then
		POSTDISPLAY="$orig_postdisplay"
		return $retval
	fi

	# Optimize if manually typing in the suggestion or if buffer hasn't changed
	if [[ "$BUFFER" = "$orig_buffer"* && "$orig_postdisplay" = "${BUFFER:$#orig_buffer}"* ]]; then
		POSTDISPLAY="${orig_postdisplay:$(($#BUFFER - $#orig_buffer))}"
		return $retval
	fi

	# Bail out if suggestions are disabled
	if (( ${+_ZSH_AUTOSUGGEST_DISABLED} )); then
		return $?
	fi

	# Get a new suggestion if the buffer is not empty after modification
	if (( $#BUFFER > 0 )); then
		if [[ -z "$ZSH_AUTOSUGGEST_BUFFER_MAX_SIZE" ]] || (( $#BUFFER <= $ZSH_AUTOSUGGEST_BUFFER_MAX_SIZE )); then
			_zsh_autosuggest_fetch
		fi
	fi

	return $retval
}

# Fetch a new suggestion based on what's currently in the buffer
_zsh_autosuggest_fetch() {
	if (( ${+ZSH_AUTOSUGGEST_USE_ASYNC} )); then
		_zsh_autosuggest_async_request "$BUFFER"
	else
		local suggestion
		_zsh_autosuggest_fetch_suggestion "$BUFFER"
		_zsh_autosuggest_suggest "$suggestion"
	fi
}

# Offer a suggestion
_zsh_autosuggest_suggest() {
	emulate -L zsh

	local suggestion="$1"

	if [[ -n "$suggestion" ]] && (( $#BUFFER )); then
		POSTDISPLAY="${suggestion#$BUFFER}"
	else
		unset POSTDISPLAY
	fi
}

# Accept the entire suggestion
_zsh_autosuggest_accept() {
	local -i retval max_cursor_pos=$#BUFFER

	# When vicmd keymap is active, the cursor can't move all the way
	# to the end of the buffer
	if [[ "$KEYMAP" = "vicmd" ]]; then
		max_cursor_pos=$((max_cursor_pos - 1))
	fi

	# If we're not in a valid state to accept a suggestion, just run the
	# original widget and bail out
	if (( $CURSOR != $max_cursor_pos || !$#POSTDISPLAY )); then
		_zsh_autosuggest_invoke_original_widget $@
		return
	fi

	# Only accept if the cursor is at the end of the buffer
	# Add the suggestion to the buffer
	BUFFER="$BUFFER$POSTDISPLAY"

	# Remove the suggestion
	unset POSTDISPLAY

	# Run the original widget before manually moving the cursor so that the
	# cursor movement doesn't make the widget do something unexpected
	_zsh_autosuggest_invoke_original_widget $@
	retval=$?

	# Move the cursor to the end of the buffer
	if [[ "$KEYMAP" = "vicmd" ]]; then
		CURSOR=$(($#BUFFER - 1))
	else
		CURSOR=$#BUFFER
	fi

	return $retval
}

# Accept the entire suggestion and execute it
_zsh_autosuggest_execute() {
	# Add the suggestion to the buffer
	BUFFER="$BUFFER$POSTDISPLAY"

	# Remove the suggestion
	unset POSTDISPLAY

	# Call the original `accept-line` to handle syntax highlighting or
	# other potential custom behavior
	_zsh_autosuggest_invoke_original_widget "accept-line"
}

# Partially accept the suggestion
_zsh_autosuggest_partial_accept() {
	local -i retval cursor_loc

	# Save the contents of the buffer so we can restore later if needed
	local original_buffer="$BUFFER"

	# Temporarily accept the suggestion.
	BUFFER="$BUFFER$POSTDISPLAY"

	# Original widget moves the cursor
	_zsh_autosuggest_invoke_original_widget $@
	retval=$?

	# Normalize cursor location across vi/emacs modes
	cursor_loc=$CURSOR
	if [[ "$KEYMAP" = "vicmd" ]]; then
		cursor_loc=$((cursor_loc + 1))
	fi

	# If we've moved past the end of the original buffer
	if (( $cursor_loc > $#original_buffer )); then
		# Set POSTDISPLAY to text right of the cursor
		POSTDISPLAY="${BUFFER[$(($cursor_loc + 1)),$#BUFFER]}"

		# Clip the buffer at the cursor
		BUFFER="${BUFFER[1,$cursor_loc]}"
	else
		# Restore the original buffer
		BUFFER="$original_buffer"
	fi

	return $retval
}

() {
	typeset -ga _ZSH_AUTOSUGGEST_BUILTIN_ACTIONS

	_ZSH_AUTOSUGGEST_BUILTIN_ACTIONS=(
		clear
		fetch
		suggest
		accept
		execute
		enable
		disable
		toggle
	)

	local action
	for action in $_ZSH_AUTOSUGGEST_BUILTIN_ACTIONS modify partial_accept; do
		eval "_zsh_autosuggest_widget_$action() {
			local -i retval

			_zsh_autosuggest_highlight_reset

			_zsh_autosuggest_$action \$@
			retval=\$?

			_zsh_autosuggest_highlight_apply

			zle -R

			return \$retval
		}"
	done

	for action in $_ZSH_AUTOSUGGEST_BUILTIN_ACTIONS; do
		zle -N autosuggest-$action _zsh_autosuggest_widget_$action
	done
}

#--------------------------------------------------------------------#
# Completion Suggestion Strategy                                     #
#--------------------------------------------------------------------#
# Fetches a suggestion from the completion engine
#

_zsh_autosuggest_capture_postcompletion() {
	# Always insert the first completion into the buffer
	compstate[insert]=1

	# Don't list completions
	unset 'compstate[list]'
}

_zsh_autosuggest_capture_completion_widget() {
	# Add a post-completion hook to be called after all completions have been
	# gathered. The hook can modify compstate to affect what is done with the
	# gathered completions.
	local -a +h comppostfuncs
	comppostfuncs=(_zsh_autosuggest_capture_postcompletion)

	# Only capture completions at the end of the buffer
	CURSOR=$#BUFFER

	# Run the original widget wrapping `.complete-word` so we don't
	# recursively try to fetch suggestions, since our pty is forked
	# after autosuggestions is initialized.
	zle -- ${(k)widgets[(r)completion:.complete-word:_main_complete]}

	if is-at-least 5.0.3; then
		# Don't do any cr/lf transformations. We need to do this immediately before
		# output because if we do it in setup, onlcr will be re-enabled when we enter
		# vared in the async code path. There is a bug in zpty module in older versions
		# where the tty is not properly attached to the pty slave, resulting in stty
		# getting stopped with a SIGTTOU. See zsh-workers thread 31660 and upstream
		# commit f75904a38
		stty -onlcr -ocrnl -F /dev/tty
	fi

	# The completion has been added, print the buffer as the suggestion
	echo -nE - $'\0'$BUFFER$'\0'
}

zle -N autosuggest-capture-completion _zsh_autosuggest_capture_completion_widget

_zsh_autosuggest_capture_setup() {
	# There is a bug in zpty module in older zsh versions by which a
	# zpty that exits will kill all zpty processes that were forked
	# before it. Here we set up a zsh exit hook to SIGKILL the zpty
	# process immediately, before it has a chance to kill any other
	# zpty processes.
	if ! is-at-least 5.4; then
		zshexit() {
			# The zsh builtin `kill` fails sometimes in older versions
			# https://unix.stackexchange.com/a/477647/156673
			kill -KILL $$ 2>&- || command kill -KILL $$

			# Block for long enough for the signal to come through
			sleep 1
		}
	fi

	# Try to avoid any suggestions that wouldn't match the prefix
	zstyle ':completion:*' matcher-list ''
	zstyle ':completion:*' path-completion false
	zstyle ':completion:*' max-errors 0 not-numeric

	bindkey '^I' autosuggest-capture-completion
}

_zsh_autosuggest_capture_completion_sync() {
	_zsh_autosuggest_capture_setup

	zle autosuggest-capture-completion
}

_zsh_autosuggest_capture_completion_async() {
	_zsh_autosuggest_capture_setup

	zmodload zsh/parameter 2>/dev/null || return # For `$functions`

	# Make vared completion work as if for a normal command line
	# https://stackoverflow.com/a/7057118/154703
	autoload +X _complete
	functions[_original_complete]=$functions[_complete]
	function _complete() {
		unset 'compstate[vared]'
		_original_complete "$@"
	}

	# Open zle with buffer set so we can capture completions for it
	vared 1
}

_zsh_autosuggest_strategy_completion() {
	# Reset options to defaults and enable LOCAL_OPTIONS
	emulate -L zsh

	# Enable extended glob for completion ignore pattern
	setopt EXTENDED_GLOB

	typeset -g suggestion
	local line REPLY

	# Exit if we don't have completions
	whence compdef >/dev/null || return

	# Exit if we don't have zpty
	zmodload zsh/zpty 2>/dev/null || return

	# Exit if our search string matches the ignore pattern
	[[ -n "$ZSH_AUTOSUGGEST_COMPLETION_IGNORE" ]] && [[ "$1" == $~ZSH_AUTOSUGGEST_COMPLETION_IGNORE ]] && return

	# Zle will be inactive if we are in async mode
	if zle; then
		zpty $ZSH_AUTOSUGGEST_COMPLETIONS_PTY_NAME _zsh_autosuggest_capture_completion_sync
	else
		zpty $ZSH_AUTOSUGGEST_COMPLETIONS_PTY_NAME _zsh_autosuggest_capture_completion_async "\$1"
		zpty -w $ZSH_AUTOSUGGEST_COMPLETIONS_PTY_NAME $'\t'
	fi

	{
		# The completion result is surrounded by null bytes, so read the
		# content between the first two null bytes.
		zpty -r $ZSH_AUTOSUGGEST_COMPLETIONS_PTY_NAME line '*'$'\0''*'$'\0'

		# Extract the suggestion from between the null bytes.  On older
		# versions of zsh (older than 5.3), we sometimes get extra bytes after
		# the second null byte, so trim those off the end.
		# See http://www.zsh.org/mla/workers/2015/msg03290.html
		suggestion="${${(@0)line}[2]}"
	} always {
		# Destroy the pty
		zpty -d $ZSH_AUTOSUGGEST_COMPLETIONS_PTY_NAME
	}
}

#--------------------------------------------------------------------#
# History Suggestion Strategy                                        #
#--------------------------------------------------------------------#
# Suggests the most recent history item that matches the given
# prefix.
#

_zsh_autosuggest_strategy_history() {
	# Reset options to defaults and enable LOCAL_OPTIONS
	emulate -L zsh

	# Enable globbing flags so that we can use (#m) and (x~y) glob operator
	setopt EXTENDED_GLOB

	# Escape backslashes and all of the glob operators so we can use
	# this string as a pattern to search the $history associative array.
	# - (#m) globbing flag enables setting references for match data
	# TODO: Use (b) flag when we can drop support for zsh older than v5.0.8
	local prefix="${1//(#m)[\\*?[\]<>()|^~#]/\\$MATCH}"

	# Get the history items that match the prefix, excluding those that match
	# the ignore pattern
	local pattern="$prefix*"
	if [[ -n $ZSH_AUTOSUGGEST_HISTORY_IGNORE ]]; then
		pattern="($pattern)~($ZSH_AUTOSUGGEST_HISTORY_IGNORE)"
	fi

	# Give the first history item matching the pattern as the suggestion
	# - (r) subscript flag makes the pattern match on values
	typeset -g suggestion="${history[(r)$pattern]}"
}

_zsh_autosuggest_strategy_match_prev_cmd() {
	# Reset options to defaults and enable LOCAL_OPTIONS
	emulate -L zsh

	# Enable globbing flags so that we can use (#m) and (x~y) glob operator
	setopt EXTENDED_GLOB

	# TODO: Use (b) flag when we can drop support for zsh older than v5.0.8
	local prefix="${1//(#m)[\\*?[\]<>()|^~#]/\\$MATCH}"

	# Get the history items that match the prefix, excluding those that match
	# the ignore pattern
	local pattern="$prefix*"
	if [[ -n $ZSH_AUTOSUGGEST_HISTORY_IGNORE ]]; then
		pattern="($pattern)~($ZSH_AUTOSUGGEST_HISTORY_IGNORE)"
	fi

	# Get all history event numbers that correspond to history
	# entries that match the pattern
	local history_match_keys
	history_match_keys=(${(k)history[(R)$~pattern]})

	# By default we use the first history number (most recent history entry)
	local histkey="${history_match_keys[1]}"

	# Get the previously executed command
	local prev_cmd="$(_zsh_autosuggest_escape_command "${history[$((HISTCMD-1))]}")"

	# Iterate up to the first 200 history event numbers that match $prefix
	for key in "${(@)history_match_keys[1,200]}"; do
		# Stop if we ran out of history
		[[ $key -gt 1 ]] || break

		# See if the history entry preceding the suggestion matches the
		# previous command, and use it if it does
		if [[ "${history[$((key - 1))]}" == "$prev_cmd" ]]; then
			histkey="$key"
			break
		fi
	done

	# Give back the matched history entry
	typeset -g suggestion="$history[$histkey]"
}

#--------------------------------------------------------------------#
# Fetch Suggestion                                                   #
#--------------------------------------------------------------------#
# Loops through all specified strategies and returns a suggestion
# from the first strategy to provide one.
#

_zsh_autosuggest_fetch_suggestion() {
	typeset -g suggestion
	local -a strategies
	local strategy

	# Ensure we are working with an array
	strategies=(${=ZSH_AUTOSUGGEST_STRATEGY})

	for strategy in $strategies; do
		# Try to get a suggestion from this strategy
		_zsh_autosuggest_strategy_$strategy "$1"

		# Ensure the suggestion matches the prefix
		[[ "$suggestion" != "$1"* ]] && unset suggestion

		# Break once we've found a valid suggestion
		[[ -n "$suggestion" ]] && break
	done
}

#--------------------------------------------------------------------#
# Async                                                              #
#--------------------------------------------------------------------#

_zsh_autosuggest_async_request() {
	zmodload zsh/system 2>/dev/null # For `$sysparams`

	typeset -g _ZSH_AUTOSUGGEST_ASYNC_FD _ZSH_AUTOSUGGEST_CHILD_PID

	# If we've got a pending request, cancel it
	if [[ -n "$_ZSH_AUTOSUGGEST_ASYNC_FD" ]] && { true <&$_ZSH_AUTOSUGGEST_ASYNC_FD } 2>/dev/null; then
		# Close the file descriptor and remove the handler
		exec {_ZSH_AUTOSUGGEST_ASYNC_FD}<&-
		zle -F $_ZSH_AUTOSUGGEST_ASYNC_FD

		# We won't know the pid unless the user has zsh/system module installed
		if [[ -n "$_ZSH_AUTOSUGGEST_CHILD_PID" ]]; then
			# Zsh will make a new process group for the child process only if job
			# control is enabled (MONITOR option)
			if [[ -o MONITOR ]]; then
				# Send the signal to the process group to kill any processes that may
				# have been forked by the suggestion strategy
				kill -TERM -$_ZSH_AUTOSUGGEST_CHILD_PID 2>/dev/null
			else
				# Kill just the child process since it wasn't placed in a new process
				# group. If the suggestion strategy forked any child processes they may
				# be orphaned and left behind.
				kill -TERM $_ZSH_AUTOSUGGEST_CHILD_PID 2>/dev/null
			fi
		fi
	fi

	# Fork a process to fetch a suggestion and open a pipe to read from it
	exec {_ZSH_AUTOSUGGEST_ASYNC_FD}< <(
		# Tell parent process our pid
		echo $sysparams[pid]

		# Fetch and print the suggestion
		local suggestion
		_zsh_autosuggest_fetch_suggestion "$1"
		echo -nE "$suggestion"
	)

	# There's a weird bug here where ^C stops working unless we force a fork
	# See https://github.com/zsh-users/zsh-autosuggestions/issues/364
	autoload -Uz is-at-least
	is-at-least 5.8 || command true

	# Read the pid from the child process
	read _ZSH_AUTOSUGGEST_CHILD_PID <&$_ZSH_AUTOSUGGEST_ASYNC_FD

	# When the fd is readable, call the response handler
	zle -F "$_ZSH_AUTOSUGGEST_ASYNC_FD" _zsh_autosuggest_async_response
}

# Called when new data is ready to be read from the pipe
# First arg will be fd ready for reading
# Second arg will be passed in case of error
_zsh_autosuggest_async_response() {
	emulate -L zsh

	local suggestion

	if [[ -z "$2" || "$2" == "hup" ]]; then
		# Read everything from the fd and give it as a suggestion
		IFS='' read -rd '' -u $1 suggestion
		zle autosuggest-suggest -- "$suggestion"

		# Close the fd
		exec {1}<&-
	fi

	# Always remove the handler
	zle -F "$1"
}

#--------------------------------------------------------------------#
# Start                                                              #
#--------------------------------------------------------------------#

# Start the autosuggestion widgets
_zsh_autosuggest_start() {
	# By default we re-bind widgets on every precmd to ensure we wrap other
	# wrappers. Specifically, highlighting breaks if our widgets are wrapped by
	# zsh-syntax-highlighting widgets. This also allows modifications to the
	# widget list variables to take effect on the next precmd. However this has
	# a decent performance hit, so users can set ZSH_AUTOSUGGEST_MANUAL_REBIND
	# to disable the automatic re-binding.
	if (( ${+ZSH_AUTOSUGGEST_MANUAL_REBIND} )); then
		add-zsh-hook -d precmd _zsh_autosuggest_start
	fi

	_zsh_autosuggest_bind_widgets
}

# Mark for auto-loading the functions that we use
autoload -Uz add-zsh-hook is-at-least

# Automatically enable asynchronous mode in newer versions of zsh. Disable for
# older versions because there is a bug when using async mode where ^C does not
# work immediately after fetching a suggestion.
# See https://github.com/zsh-users/zsh-autosuggestions/issues/364
if is-at-least 5.0.8; then
	typeset -g ZSH_AUTOSUGGEST_USE_ASYNC=
fi

# Start the autosuggestion widgets on the next precmd
add-zsh-hook precmd _zsh_autosuggest_start

#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
