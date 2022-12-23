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
source $CONFIG/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh
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
